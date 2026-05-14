using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer.Processors
{
    internal class LicensePatcher : ProcessorBase
    {
        private readonly List<(uint Token, string ValueSpec)> _patches = new List<(uint Token, string ValueSpec)>();

        // Built-in patch table for Eazfuscator.NET 2026.1.x (build 2026.1.797.42414).
        // Tokens are metadata-specific; supply --eazfuscator-patch-table to override for other builds.
        private static readonly (uint Token, string Spec, string Label)[] _eaz2026Patches =
        {
            (0x06007BE0, "true",           "EvaluateOnce<bool> stream compute → true"),
            (0x06008E0A, "true",           "secondary license validator → true"),
            (0x06007BDE, "int:7",          "edition int getter → 7 (max)"),
            (0x06007BDF, "int:7",          "edition int getter (bool overload) → 7"),
            (0x06006BA1, "int:7",          "edition name parser → 7 (max edition)"),
            (0x06006BAE, "true",           "enterprise feature gate → true"),
            (0x0600941F, "bool-args-false","eval state notifier: force isEvaluation/isWatermarked false"),
            (0x06009418, "void",           "VM warning callback → no-op"),
            (0x06009430, "bool-args-false","obfuscation context builder: force eval bools false"),
            (0x06001CC2, "void",           "timer callback → no-op (suppress EF-4008)"),
            (0x06001CBF, "void",           "timer starter CBF → no-op"),
            (0x06001CC0, "void",           "timer starter CC0 → no-op"),
        };

        private static readonly string[] LicenseKeywords =
        {
            "trial", "evaluation", "eval", "license", "licensed", "licensing",
            "expir", "activation", "unlicensed", "watermark", "water-mark",
            "register", "registration", "product.key", "productkey", "serial",
            "genuine", "not.licensed", "notlicensed"
        };

        private static readonly string[] TelemetryKeywords =
        {
            "ceip", "telemetry", "telmetry", "tracking", "analytics",
            "reportusage", "report.use", "phone.home", "phonehome",
            "instrumentation", "diagnostic.data", "diagnosticdata"
        };

        private static readonly string[] GateKeywords =
        {
            "deterministic", "deterministicobfuscation", "deterministic.obfuscation",
            "site.license", "sitelicense", "enterprise", "enterprise.feature",
            "premium", "ultimate", "pro.feature", "professionaledition",
            "site.wide", "siteli", "site_li"
        };

        protected override void InitializeInternal()
        {
            if (!Flags.StripLicenseTelemetry && !Flags.PatchEazfuscator && !Flags.AnalyzeLicense)
                throw new Exception("Neither --strip-license-telemetry, --patch-eazfuscator, nor --analyze-license specified");

            if (Flags.PatchEazfuscator)
                Console.WriteLine("  [LicensePatcher] Eazfuscator self-patching mode active");
            else if (Flags.AnalyzeLicense)
                Console.WriteLine("  [LicensePatcher] Analyze-only mode (no patches applied)");
            else
                Console.WriteLine("  [LicensePatcher] Scanning for license/telemetry code...");
        }

        protected override void ProcessInternal()
        {
            if (Flags.PatchEazfuscator)
            {
                ProcessEazfuscatorSelfPatch();
                return;
            }

            var module = (ModuleDefMD)Ctx.Module;
            var results = ScanAssembly(module);

            if (results.Count == 0)
            {
                Console.WriteLine("  [LicensePatcher] No license/telemetry/gate candidates found.");
                return;
            }

            Console.WriteLine($"  [LicensePatcher] Found {results.Count} candidates:");

            if (Flags.AnalyzeLicense)
            {
                foreach (var (method, reason, valueSpec) in results)
                    Console.WriteLine($"    candidate 0x{method.MDToken.Raw:X8} ({reason}) -> {valueSpec}  [{SafeMethodName(method)}]");
                Console.WriteLine($"  [LicensePatcher] Analysis complete. Use --patch with above tokens to patch.");
                return;
            }

            foreach (var (method, reason, valueSpec) in results)
            {
                try
                {
                    ReturnPatcher.Apply(module, method.MDToken.Raw, valueSpec);
                    _patches.Add((method.MDToken.Raw, valueSpec));
                    Console.WriteLine($"    -> patched 0x{method.MDToken.Raw:X8} ({reason}): {valueSpec}");
                }
                catch (Exception ex)
                {
                    // If the normal ReturnPatcher fails (e.g. type mismatch on Nullable types),
                    // try a manual IL patch for known special cases.
                    if (TryManualPatch(module, method, reason))
                    {
                        _patches.Add((method.MDToken.Raw, valueSpec));
                        Console.WriteLine($"    -> patched 0x{method.MDToken.Raw:X8} ({reason}): {valueSpec} (manual)");
                    }
                    else
                    {
                        Console.WriteLine($"    -> SKIP 0x{method.MDToken.Raw:X8} ({reason}): {ex.Message}");
                    }
                }
            }

            Console.WriteLine($"  [LicensePatcher] Patched {_patches.Count} methods total.");
        }

        protected override void CleanupInternal()
        {
        }

        private void ProcessEazfuscatorSelfPatch()
        {
            Console.WriteLine("  [LicensePatcher] Processing Eazfuscator assembly...");

            var module = (ModuleDefMD)Ctx.Module;

            List<(uint Token, string Spec, string Label)> table;
            if (Flags.EazfuscatorPatches.Count > 0)
            {
                Console.WriteLine($"  [LicensePatcher] Using {Flags.EazfuscatorPatches.Count} entries from --eazfuscator-patch-table.");
                table = Flags.EazfuscatorPatches
                    .Select(p => (p.Token, p.ValueSpec, $"manual 0x{p.Token:X8}"))
                    .ToList();
            }
            else
            {
                Console.WriteLine("  [LicensePatcher] Running heuristic scan for license/eval patch targets...");
                table = ScanEazfuscatorDll(module);
                Console.WriteLine($"  [LicensePatcher] Heuristic scan found {table.Count} candidate(s).");

                // Supplement with built-in table entries whose tokens still resolve but were
                // not covered by the heuristic (e.g. timer starters buried in VM dispatch).
                var heuristicToks = new HashSet<uint>(table.Select(e => e.Token));
                int topUp = 0;
                foreach (var (tok, spec, lbl) in _eaz2026Patches)
                {
                    if (heuristicToks.Contains(tok)) continue;
                    if (module.ResolveToken(tok) is MethodDef)
                    {
                        table.Add((tok, spec, $"built-in table (heuristic miss): {lbl}"));
                        topUp++;
                    }
                }
                if (topUp > 0)
                    Console.WriteLine($"  [LicensePatcher] Built-in table supplemented {topUp} additional entry/ies.");
            }

            foreach (var (token, spec, label) in table)
            {
                try
                {
                    ReturnPatcher.Apply(module, token, spec);
                    _patches.Add((token, spec));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    -> FAIL 0x{token:X8}={spec}: {ex.Message}  ({label})");
                }
            }

            Console.WriteLine($"  [LicensePatcher] Applied {_patches.Count} patches total.");
        }

        // ─── Heuristic Eazfuscator-DLL patch detection ───────────────────────────

        private static List<(uint Token, string Spec, string Label)> ScanEazfuscatorDll(ModuleDefMD module)
        {
            var results = new List<(uint, string, string)>();
            var seen    = new HashSet<uint>();

            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;
                    uint tok = method.MDToken.Raw;
                    if (!seen.Add(tok)) continue;

                    var instrs = method.Body.Instructions;

                    if (EazDetectVmWarningCallback(method, instrs, out var spec, out var label) ||
                        EazDetectBoolArgsPack(method, instrs, out spec, out label) ||
                        EazDetectEditionParser(method, instrs, out spec, out label) ||
                        EazDetectEnterpriseGate(method, instrs, out spec, out label) ||
                        EazDetectLicenseBoolSignature(method, instrs, out spec, out label) ||
                        EazDetectLicenseCacheCheck(method, instrs, out spec, out label))
                    {
                        Console.WriteLine($"    heuristic 0x{tok:X8} -> {spec,-20} ({label})");
                        results.Add((tok, spec, label));
                    }
                }
            }

            return results;
        }

        // void M(bool) — instance — short forwarding stub that passes the bool arg directly to a callee.
        private static bool EazDetectVmWarningCallback(MethodDef m, IList<Instruction> instrs, out string spec, out string label)
        {
            spec = null; label = null;
            if (m.IsStatic || m.ReturnType?.FullName != "System.Void") return false;

            var userParams = m.Parameters.Skip(1).ToList();
            if (userParams.Count != 1 || userParams[0].Type?.FullName != "System.Boolean") return false;
            if (instrs.Count > 15) return false;

            for (int i = 0; i < instrs.Count - 1; i++)
            {
                int idx = EazArgIdx(instrs[i]);
                if (idx == 1 && (instrs[i + 1].OpCode.Code == Code.Call || instrs[i + 1].OpCode.Code == Code.Callvirt))
                {
                    spec  = "void";
                    label = "VM warning callback void(bool) → no-op";
                    return true;
                }
            }
            return false;
        }

        // Any method (void or non-void) where ≥3 distinct argument indices are each immediately
        // followed by "box System.Boolean" — the eval-state notifier and context-builder pattern.
        private static bool EazDetectBoolArgsPack(MethodDef m, IList<Instruction> instrs, out string spec, out string label)
        {
            spec = null; label = null;

            var boxedArgs = new HashSet<int>();
            for (int i = 0; i < instrs.Count - 1; i++)
            {
                int idx = EazArgIdx(instrs[i]);
                if (idx < 0) continue;
                if (instrs[i + 1].OpCode.Code == Code.Box &&
                    (instrs[i + 1].Operand as ITypeDefOrRef)?.FullName == "System.Boolean")
                    boxedArgs.Add(idx);
            }

            if (boxedArgs.Count < 3) return false;

            bool isVoid = m.ReturnType?.FullName == "System.Void";
            spec  = "bool-args-false";
            label = isVoid
                ? $"eval state notifier ({boxedArgs.Count} bool args packed) → all false"
                : $"context builder ({boxedArgs.Count} bool args packed) → all false";
            return true;
        }

        // int M(...) with branches where ALL integer constants are edition codes
        // {-1, 0, 1–7, int.MaxValue} and at least 3 of {1–7} appear.
        // Any non-edition constant (hash magic, bit flags, etc.) immediately disqualifies the method,
        // which eliminates GetHashCode, Compare, and similar methods that share the branch pattern.
        private static bool EazDetectEditionParser(MethodDef m, IList<Instruction> instrs, out string spec, out string label)
        {
            spec = null; label = null;
            if (m.ReturnType?.FullName != "System.Int32") return false;
            if (instrs.Count < 12) return false; // trivial stubs can't be a multi-case parser

            var allowedConstants = new HashSet<int> { -1, 0, 1, 2, 3, 4, 5, 6, 7, int.MaxValue };
            var found = new HashSet<int>();
            bool hasBranch = false;

            foreach (var instr in instrs)
            {
                var code = instr.OpCode.Code;
                int? cv = null;
                switch (code)
                {
                    case Code.Ldc_I4:    cv = (int)instr.Operand; break;
                    case Code.Ldc_I4_0:  cv = 0; break;
                    case Code.Ldc_I4_1:  cv = 1; break;
                    case Code.Ldc_I4_2:  cv = 2; break;
                    case Code.Ldc_I4_3:  cv = 3; break;
                    case Code.Ldc_I4_4:  cv = 4; break;
                    case Code.Ldc_I4_5:  cv = 5; break;
                    case Code.Ldc_I4_6:  cv = 6; break;
                    case Code.Ldc_I4_7:  cv = 7; break;
                    case Code.Ldc_I4_8:  cv = 8; break;
                    case Code.Ldc_I4_M1: cv = -1; break;
                    case Code.Ldc_I4_S:  cv = (sbyte)instr.Operand; break;
                }

                if (cv.HasValue)
                {
                    if (!allowedConstants.Contains(cv.Value))
                        return false; // first non-edition constant disqualifies
                    found.Add(cv.Value);
                }

                if (code == Code.Brtrue || code == Code.Brtrue_S ||
                    code == Code.Brfalse || code == Code.Brfalse_S ||
                    code == Code.Beq || code == Code.Beq_S ||
                    code == Code.Bne_Un || code == Code.Bne_Un_S ||
                    code == Code.Switch)
                    hasBranch = true;
            }

            if (!hasBranch) return false;
            // int.MaxValue is the "unknown/eval edition" sentinel — must be present in a real parser.
            if (!found.Contains(int.MaxValue)) return false;
            int editionCount = found.Count(v => v >= 1 && v <= 7);
            if (editionCount < 3) return false;

            spec  = "int:7";
            label = $"edition parser (codes {{{string.Join(",", found.Where(v => v >= 1 && v <= 7).OrderBy(x => x))}}},MaxValue) → 7";
            return true;
        }

        // bool M(...) that looks up ObfuscationAttribute via GetCustomAttribute(s)/IsDefined —
        // the per-assembly enterprise feature gate.  Methods that take ObfuscationAttribute as
        // their own parameter are utility helpers, not the gate, and are excluded.
        private static bool EazDetectEnterpriseGate(MethodDef m, IList<Instruction> instrs, out string spec, out string label)
        {
            spec = null; label = null;
            if (m.ReturnType?.FullName != "System.Boolean") return false;

            // Skip utility helpers that take ObfuscationAttribute directly as a parameter.
            foreach (var p in m.Parameters)
            {
                if (p.Type?.FullName?.Contains("ObfuscationAttribute") == true)
                    return false;
            }

            bool refsObfuscationAttr = false;
            bool callsGetCustomAttr  = false;

            foreach (var instr in instrs)
            {
                var code = instr.OpCode.Code;
                if (code != Code.Call && code != Code.Callvirt && code != Code.Ldtoken) continue;

                string typeName = (instr.Operand as IMethod)?.DeclaringType?.FullName
                               ?? (instr.Operand as ITypeDefOrRef)?.FullName
                               ?? "";
                string methName = (instr.Operand as IMethod)?.Name ?? "";

                if (typeName.Contains("ObfuscationAttribute") || methName.Contains("ObfuscationAttribute"))
                    refsObfuscationAttr = true;
                if (methName.Contains("GetCustomAttribute") || methName == "IsDefined")
                    callsGetCustomAttr = true;
            }

            if (!refsObfuscationAttr || !callsGetCustomAttr) return false;

            spec  = "true";
            label = "enterprise feature gate (GetCustomAttribute + ObfuscationAttribute) → true";
            return true;
        }

        // bool M(Nullable<int>, bool) — the EvaluateOnce<bool> stream compute method.
        // The parameter types are stable even after obfuscation because they reference BCL types.
        private static bool EazDetectLicenseBoolSignature(MethodDef m, IList<Instruction> instrs, out string spec, out string label)
        {
            spec = null; label = null;
            if (m.ReturnType?.FullName != "System.Boolean") return false;

            var userParams = m.IsStatic ? m.Parameters.ToList() : m.Parameters.Skip(1).ToList();
            if (userParams.Count != 2) return false;

            var p0 = userParams[0].Type?.FullName ?? "";
            var p1 = userParams[1].Type?.FullName ?? "";
            if ((p0.Contains("Nullable") && p0.Contains("Int32")) && p1 == "System.Boolean")
            {
                spec  = "true";
                label = "license compute bool(Nullable<int>, bool) → true";
                return true;
            }
            return false;
        }

        // bool M(...) that calls into System.Runtime.Caching.MemoryCache (or similar) —
        // the secondary cached license validator.
        private static bool EazDetectLicenseCacheCheck(MethodDef m, IList<Instruction> instrs, out string spec, out string label)
        {
            spec = null; label = null;
            if (m.ReturnType?.FullName != "System.Boolean") return false;

            foreach (var instr in instrs)
            {
                var code = instr.OpCode.Code;
                if (code != Code.Call && code != Code.Callvirt && code != Code.Newobj) continue;
                var typeName = (instr.Operand as IMethod)?.DeclaringType?.FullName ?? "";
                if (typeName.Contains("MemoryCache") || typeName.Contains("ObjectCache"))
                {
                    spec  = "true";
                    label = "license cache check (MemoryCache/ObjectCache) → true";
                    return true;
                }
            }
            return false;
        }

        // Returns the 0-based parameter index for an arg-load instruction, or -1 if not an arg load.
        private static int EazArgIdx(Instruction instr)
        {
            switch (instr.OpCode.Code)
            {
                case Code.Ldarg_0: return 0;
                case Code.Ldarg_1: return 1;
                case Code.Ldarg_2: return 2;
                case Code.Ldarg_3: return 3;
                case Code.Ldarg_S:
                case Code.Ldarg:
                    return instr.Operand is Parameter p ? p.Index : -1;
                default:           return -1;
            }
        }

        private List<(MethodDef Method, string Reason, string ValueSpec)> ScanAssembly(ModuleDefMD module)
        {
            var results = new List<(MethodDef, string, string)>();
            var visited = new HashSet<uint>();

            int totalMethods = 0;
            int analyzedMethods = 0;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions)
                        continue;

                    uint token = method.MDToken.Raw;
                    if (!visited.Add(token))
                        continue;

                    totalMethods++;

                    // Quick pre-scan: skip methods unlikely to be license-related
                    var instrs = method.Body.Instructions;

                    // Methods without strings, call/callvirt, date ops, or assembly refs are unlikely
                    bool hasString = false;
                    bool hasCall = false;
                    bool hasDateRef = false;
                    bool hasGetExecAsm = false;

                    for (int i = 0; i < instrs.Count; i++)
                    {
                        var code = instrs[i].OpCode.Code;
                        if (code == Code.Ldstr) hasString = true;
                        else if (code == Code.Call || code == Code.Callvirt) hasCall = true;
                        else if (code == Code.Newobj || code == Code.Call || code == Code.Callvirt)
                        {
                            if ((instrs[i].Operand as IMethod)?.Name == ".ctor")
                            {
                                var ctorType = (instrs[i].Operand as IMethod)?.DeclaringType?.FullName ?? "";
                                if (ctorType == "System.DateTime" || ctorType == "System.TimeSpan")
                                    hasDateRef = true;
                            }
                        }

                        if (hasCall && (instrs[i].Operand as IMethod)?.Name == "GetExecutingAssembly")
                            hasGetExecAsm = true;

                        // Early exit if we have enough hints
                        if (hasString || hasDateRef || hasGetExecAsm)
                            break;
                    }

                    if (!hasString && !hasDateRef && !hasGetExecAsm)
                    {
                        // For bool-returning methods with calls, still check deeper
                        if (!(method.ReturnType?.FullName == "System.Boolean" && hasCall))
                            continue;
                    }

                    analyzedMethods++;

                    if (analyzedMethods % 500 == 0)
                    {
                        Console.Write($"\r  [LicensePatcher] Scanned {analyzedMethods}/{totalMethods} methods...");
                    }

                    var reason = ClassifyMethod(method, instrs);
                    if (reason == null)
                        continue;

                    string spec = InferReturnSpec(method, reason);
                    if (spec == null)
                        continue;

                    results.Add((method, reason, spec));
                }
            }

            stopwatch.Stop();

            if (analyzedMethods >= 500)
                Console.Write("\r");

            Console.WriteLine($"  [LicensePatcher] Scanned {analyzedMethods} methods out of {totalMethods} total in {stopwatch.Elapsed.TotalSeconds:F1}s.");
            return results;
        }

        private string ClassifyMethod(MethodDef method, IList<Instruction> instrs = null)
        {
            if (!method.HasBody || !method.Body.HasInstructions)
                return null;

            instrs ??= method.Body.Instructions;

            // Skip entry points and runtime-invoked methods
            if (IsRuntimeOrEntryPoint(method))
                return null;

            var returnTypeName = method.ReturnType?.FullName;

            // Collect all loaded strings and their instruction indices
            var stringEntries = new List<(int Index, string Value)>();
            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode.Code == Code.Ldstr && instrs[i].Operand is string s)
                    stringEntries.Add((i, s.ToLowerInvariant()));
            }

            // Check if any license keyword string is used in a decision context
            // (followed by call to a bool method, or used in a conditional branch)
            bool foundLicenseDecision = false;
            string foundLicenseKeyword = null;
            bool foundTelemetryDecision = false;
            string foundTelemetryKeyword = null;
            bool foundGateDecision = false;
            string foundGateKeyword = null;

            foreach (var (idx, val) in stringEntries)
            {
                // Determine the keyword category
                string kwCategory = null;
                string matchedKw = null;

                foreach (var kw in LicenseKeywords)
                {
                    if (val.Contains(kw)) { kwCategory = "license"; matchedKw = kw; break; }
                }
                if (kwCategory == null)
                {
                    foreach (var kw in TelemetryKeywords)
                    {
                        if (val.Contains(kw)) { kwCategory = "telemetry"; matchedKw = kw; break; }
                    }
                }
                if (kwCategory == null)
                {
                    foreach (var kw in GateKeywords)
                    {
                        if (val.Contains(kw)) { kwCategory = "gate"; matchedKw = kw; break; }
                    }
                }

                if (kwCategory == null)
                    continue;

                // Check if the string is used in a decision-making context:
                // Look ahead after the ldstr for how it's consumed
                bool isDecision = false;
                bool isOutputOnly = false;

                for (int j = idx + 1; j < instrs.Count && j <= idx + 5; j++)
                {
                    var nextCode = instrs[j].OpCode.Code;

                    // If the next instruction after the string is Call/Callvirt,
                    // check if it's a decision method or output method
                    if (nextCode == Code.Call || nextCode == Code.Callvirt)
                    {
                        var callee = instrs[j].Operand as IMethod;
                        if (callee != null)
                        {
                            var calleeName = callee.FullName ?? "";
                            // Output/logging methods - likely not a license check
                            if (calleeName.Contains("Console.") ||
                                calleeName.Contains("Debug.") ||
                                calleeName.Contains("Trace.") ||
                                calleeName.Contains("ILogger") ||
                                calleeName.Contains("Log.") ||
                                calleeName.Contains("WriteLine"))
                            {
                                isOutputOnly = true;
                            }
                            // Comparison/decision methods
                            else if (calleeName.Contains("String.op_Equality") ||
                                     calleeName.Contains("String.Equals") ||
                                     calleeName.Contains("Compare") ||
                                     calleeName.Contains("StartsWith") ||
                                     calleeName.Contains("Contains"))
                            {
                                isDecision = true;
                            }
                        }
                    }
                    // Direct comparison after loading a string + another value
                    else if (nextCode == Code.Ceq || nextCode == Code.Brtrue ||
                             nextCode == Code.Brtrue_S || nextCode == Code.Brfalse ||
                             nextCode == Code.Brfalse_S)
                    {
                        isDecision = true;
                    }
                }

                // If the method itself returns bool, it's likely a check method
                if (returnTypeName == "System.Boolean")
                {
                    isDecision = true;
                }
                // If the method is void (output method), it's likely reporting telemetry
                else if (returnTypeName == "System.Void" && kwCategory == "telemetry")
                {
                    isDecision = true;
                }

                if (isDecision)
                {
                    switch (kwCategory)
                    {
                        case "license":
                            foundLicenseDecision = true;
                            foundLicenseKeyword = matchedKw;
                            break;
                        case "telemetry":
                            foundTelemetryDecision = true;
                            foundTelemetryKeyword = matchedKw;
                            break;
                        case "gate":
                            foundGateDecision = true;
                            foundGateKeyword = matchedKw;
                            break;
                    }
                }
            }

            if (foundLicenseDecision)
                return $"license_string_match({foundLicenseKeyword})";
            if (foundGateDecision)
                return $"feature_gate_string({foundGateKeyword})";
            if (foundTelemetryDecision)
                return $"telemetry_string_match({foundTelemetryKeyword})";

            // Date/time based trial expiry detection
            if (returnTypeName == "System.Boolean")
            {
                bool hasDateTimeNow = false;
                bool hasDateCompare = false;
                bool hasDateNew = false;
                bool hasTimeSpanNew = false;
                bool hasGetExecAsm = false;
                bool hasCgtClt = false;

                foreach (var i in instrs)
                {
                    var code = i.OpCode.Code;
                    if (code == Code.Call || code == Code.Callvirt)
                    {
                        var mName = (i.Operand as IMethod)?.Name ?? "";
                        if (!hasDateTimeNow && (mName == "get_Now" ||
                            mName == "get_UtcNow" ||
                            mName == "get_Today"))
                            hasDateTimeNow = true;
                        if (!hasGetExecAsm && mName == "GetExecutingAssembly")
                            hasGetExecAsm = true;
                    }
                    // Detect subtraction / time arithmetic (op_Subtraction, Subtract)
                    if (!hasDateCompare && (code == Code.Call || code == Code.Callvirt) &&
                        ((i.Operand as IMethod)?.Name?.Contains("Subtract") == true ||
                         (i.Operand as IMethod)?.Name?.Contains("op_Subtraction") == true))
                        hasDateCompare = true;
                    // Detect comparison branches
                    if (!hasDateCompare && (code == Code.Blt || code == Code.Blt_S ||
                        code == Code.Bgt || code == Code.Bgt_S ||
                        code == Code.Ble || code == Code.Ble_S ||
                        code == Code.Bge || code == Code.Bge_S))
                        hasDateCompare = true;
                    // Detect comparison results (cgt, clt, ceq)
                    if (!hasCgtClt && (code == Code.Cgt || code == Code.Cgt_Un ||
                        code == Code.Clt || code == Code.Clt_Un ||
                        code == Code.Ceq))
                        hasCgtClt = true;
                    if (!hasDateNew && (code == Code.Newobj || code == Code.Call || code == Code.Callvirt) &&
                        (i.Operand as IMethod)?.Name == ".ctor" &&
                        (i.Operand as IMethod)?.DeclaringType?.FullName == "System.DateTime")
                        hasDateNew = true;
                    if (!hasTimeSpanNew && (code == Code.Newobj || code == Code.Call || code == Code.Callvirt) &&
                        (i.Operand as IMethod)?.Name == ".ctor" &&
                        (i.Operand as IMethod)?.DeclaringType?.FullName == "System.TimeSpan")
                        hasTimeSpanNew = true;
                }

                if (hasDateTimeNow && (hasDateCompare || hasCgtClt || hasDateNew || hasTimeSpanNew))
                    return "trial_expiry_check";
                if (hasGetExecAsm)
                    return "assembly_tamper_check";
            }

            return null;
        }

        private bool IsRuntimeOrEntryPoint(MethodDef method)
        {
            // Skip module constructors and entry points
            if (method.IsConstructor && method.DeclaringType != null &&
                method.DeclaringType.FullName == "<Module>")
                return true;

            if (method.Name == "Main" && method.DeclaringType != null &&
                (method.DeclaringType.FullName.Contains("Program") ||
                 method.DeclaringType.FullName.Contains("Startup")))
                return true;

            // Skip property getters/setters and event add/remove (unlikely license checks)
            if (method.IsGetter || method.IsSetter || method.IsAddOn || method.IsRemoveOn)
                return true;

            return false;
        }

        private string InferReturnSpec(MethodDef method, string reason = null)
        {
            if (method.ReturnType == null)
                return null;

            var retType = method.ReturnType.FullName;

            // Trial expiry checks should return "false" (not expired) to avoid nags
            bool isTrialCheck = reason != null && reason.Contains("trial_expiry");

            switch (retType)
            {
                case "System.Boolean":
                    return isTrialCheck ? "false" : "true";
                case "System.Int32":
                case "System.UInt32":
                case "System.Int16":
                case "System.UInt16":
                case "System.Byte":
                case "System.SByte":
                    return isTrialCheck ? "int:0" : "int:1";
                case "System.Int64":
                case "System.UInt64":
                    return isTrialCheck ? "long:0" : "long:1";
                case "System.String":
                    return "string:Licensed";
                case "System.Void":
                    return "void";
                case "System.Object":
                    return "null";
                default:
                    if (retType.Contains("License") || retType.Contains("Edition"))
                        return "int:999";

                    if (method.ReturnType.IsValueType)
                        return "int:0";

                    return "null";
            }
        }

        private bool TryManualPatch(ModuleDefMD module, MethodDef method, string reason)
        {
            if (method.ReturnType == null) return false;

            var retTypeName = method.ReturnType.FullName ?? "";

            // For Nullable<T> and other value types: return default (zero-init)
            // This produces Nullable<bool>() with HasValue=false, which is safe.
            if (method.ReturnType.IsValueType)
            {
                var body = new CilBody
                {
                    InitLocals = false,
                    MaxStack = 1
                };
                // For value types, we need to initobj and load. Use a temporary local.
                var tmpLocal = new Local(method.ReturnType);
                body.Variables.Add(tmpLocal);
                body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, tmpLocal));
                var retTypeRef = method.ReturnType.ToTypeDefOrRef();
                if (retTypeRef != null)
                    body.Instructions.Add(Instruction.Create(OpCodes.Initobj, retTypeRef));
                else
                    body.Instructions.Add(Instruction.Create(OpCodes.Initobj, (uint)0));
                body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                method.FreeMethodBody();
                method.Body = body;
                return true;
            }

            return false;
        }

        private static string SafeMethodName(MethodDef m)
        {
            try { return m.FullName; }
            catch { return "<unprintable>"; }
        }

        public IReadOnlyList<(uint Token, string ValueSpec)> AppliedPatches => _patches.AsReadOnly();
    }
}

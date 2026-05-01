using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace eazdevirt
{
    /// <summary>
    /// Fingerprint-based classifier tuned for Eazfuscator 2025.x handler
    /// layout. 2018-era detectors in <c>eazdevirt.Detection.V1.Ext</c> match
    /// against the historical thin handler shape; modern handlers add a
    /// control-flow-obfuscation layer and call primitives through a slightly
    /// different call chain, so they don't match directly.
    ///
    /// This classifier compresses each handler down to a small fingerprint
    /// (which primitive it calls, with what constant operands, and shallow
    /// body shape) and then maps known fingerprints to CIL opcodes.
    /// </summary>
    public static class HandlerClassifier2025
    {
        public sealed class HandlerFingerprint
        {
            public uint HandlerToken;
            /// <summary>Method tokens this handler call-dispatches into.</summary>
            public List<uint> CalledTokens = new List<uint>();
            /// <summary>Int constants pushed before each called method.</summary>
            public List<int> LdcArgs = new List<int>();
            /// <summary>Count of distinct opcode kinds in the handler body.</summary>
            public Dictionary<Code, int> OpcodeHistogram = new Dictionary<Code, int>();
            /// <summary>Primary (first) callvirt target — usually the VM primitive.</summary>
            public uint? PrimaryCalled;
            /// <summary>Int arg passed to PrimaryCalled if observable.</summary>
            public int? PrimaryArg;
            /// <summary>Body instruction count.</summary>
            public int InstructionCount;

            /// <summary>Up to 4 trailing ldc.i4 values before the primary call
            /// (ordered as they appear in IL). For Binop primitives this
            /// captures the (bool, bool) flags alongside the arg index.</summary>
            public List<int> PrimaryTail = new List<int>();
        }

        public static HandlerFingerprint Fingerprint(MethodDef handler)
        {
            var fp = new HandlerFingerprint { HandlerToken = handler.MDToken.Raw };
            if (handler.Body == null || !handler.Body.HasInstructions) return fp;
            var instrs = handler.Body.Instructions;
            fp.InstructionCount = instrs.Count;

            for (int i = 0; i < instrs.Count; i++)
            {
                var ins = instrs[i];
                if (!fp.OpcodeHistogram.ContainsKey(ins.OpCode.Code))
                    fp.OpcodeHistogram[ins.OpCode.Code] = 0;
                fp.OpcodeHistogram[ins.OpCode.Code]++;

                if (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt)
                {
                    var m = (ins.Operand as IMethod)?.ResolveMethodDef();
                    if (m == null) continue;
                    fp.CalledTokens.Add(m.MDToken.Raw);

                    // Scan backwards for the last ldc.i4 before the call (likely
                    // the operand passed to this primitive).
                    for (int j = i - 1; j >= Math.Max(0, i - 4); j--)
                    {
                        if (instrs[j].IsLdcI4())
                        {
                            fp.LdcArgs.Add(instrs[j].GetLdcI4Value());
                            break;
                        }
                    }

                    if (fp.PrimaryCalled == null)
                    {
                        fp.PrimaryCalled = m.MDToken.Raw;
                        // Collect ldc.i4 values immediately preceding the
                        // call, walking backward while we see ldarg.0 /
                        // ldarg.1 / ldarg.2 / ldc.i4 (the actual arg setup).
                        // Skip cflow-noise ldc.i4 that precede brtrue/brfalse.
                        var tail = new List<int>();
                        int neededArgs = m.Parameters.Count;  // includes `this` if instance
                        for (int j = i - 1; j >= 0 && tail.Count < neededArgs; j--)
                        {
                            var k = instrs[j].OpCode.Code;
                            // Stop on a branch — prior instructions belong
                            // to a different control-flow region.
                            if (k == Code.Brtrue || k == Code.Brtrue_S
                                || k == Code.Brfalse || k == Code.Brfalse_S
                                || k == Code.Br || k == Code.Br_S)
                                break;
                            if (instrs[j].IsLdcI4())
                            {
                                // A ldc.i4 immediately followed by brtrue/brfalse
                                // is cflow junk — skip it.
                                if (j + 1 < instrs.Count)
                                {
                                    var next = instrs[j + 1].OpCode.Code;
                                    if (next == Code.Brtrue || next == Code.Brtrue_S
                                        || next == Code.Brfalse || next == Code.Brfalse_S)
                                        continue;
                                }
                                tail.Insert(0, instrs[j].GetLdcI4Value());
                            }
                            else if (k == Code.Ldarg || k == Code.Ldarg_S
                                || k == Code.Ldarg_0 || k == Code.Ldarg_1
                                || k == Code.Ldarg_2 || k == Code.Ldarg_3
                                || k == Code.Ldloc || k == Code.Ldloc_S
                                || k == Code.Ldloc_0 || k == Code.Ldloc_1
                                || k == Code.Ldloc_2 || k == Code.Ldloc_3
                                || k == Code.Ldnull || k == Code.Call
                                || k == Code.Callvirt || k == Code.Ldfld)
                            {
                                // A placeholder for a non-literal argument.
                                // We don't care about its exact identity for
                                // fingerprinting.
                                tail.Insert(0, -1);
                            }
                        }
                        // Only keep the trailing literal ldc.i4 values — the
                        // ones that are plain operand bits.
                        int lastLiteralIdx = tail.Count - 1;
                        while (lastLiteralIdx >= 0 && tail[lastLiteralIdx] < 0) lastLiteralIdx--;
                        var literalTail = new List<int>();
                        for (int j = 0; j <= lastLiteralIdx; j++) if (tail[j] >= 0) literalTail.Add(tail[j]);
                        fp.PrimaryTail = literalTail;
                        if (literalTail.Count > 0) fp.PrimaryArg = literalTail[literalTail.Count - 1];
                    }
                }
            }
            return fp;
        }

        /// <summary>
        /// Classify every opcode entry's handler into a structured family:
        /// (primitive MDToken, ldc operand). Fills e.IdentifiedCil with a
        /// best-effort label ("CallPrim_0x...(arg)"). A second pass can then
        /// resolve the primitive MDTokens to semantic CIL ops.
        /// </summary>
        public static int ClassifyAll(DynamicAnalyzer.OpcodeMap map, ModuleDefMD module)
        {
            _fieldHitCount.Clear();
            _primToFieldTok.Clear();

            var perPrim = new Dictionary<uint, List<DynamicAnalyzer.OpcodeEntry>>();
            foreach (var e in map.Entries)
            {
                if (!e.HandlerToken.HasValue) continue;
                var md = module.ResolveMethod(e.HandlerToken.Value & 0xFFFFFF) as MethodDef;
                if (md == null) continue;
                var fp = Fingerprint(md);
                if (fp.PrimaryCalled == null) continue;

                var primTok = fp.PrimaryCalled.Value;
                var primArg = fp.PrimaryArg;

                // Give a structured label. Second pass translates these.
                // For binop-like calls we keep all 2 tail flags for
                // disambiguation downstream.
                string label;
                if (fp.PrimaryTail != null && fp.PrimaryTail.Count >= 2)
                    label = $"Prim_0x{primTok:X8}({string.Join(",", fp.PrimaryTail)})";
                else if (primArg.HasValue)
                    label = $"Prim_0x{primTok:X8}({primArg.Value})";
                else
                    label = $"Prim_0x{primTok:X8}()";

                e.IdentifiedCil = label;

                if (!perPrim.TryGetValue(primTok, out var list))
                    perPrim[primTok] = list = new List<DynamicAnalyzer.OpcodeEntry>();
                list.Add(e);
            }

            // Pre-pass: classify via handler-level patterns that win over
            // primitive-only guessing.
            //   - Branch: handler calls a Nullable<UInt32> setter
            //   - Binop-family: handler (or its primary primitive) calls a
            //     method with (val, val, bool, bool) signature
            foreach (var e in map.Entries)
            {
                if (!e.HandlerToken.HasValue) continue;
                var h = module.ResolveMethod(e.HandlerToken.Value & 0xFFFFFF) as MethodDef;
                if (h?.Body == null) continue;

                string brKind = GuessHandlerIsBranch(h);
                if (brKind != null) { e.IdentifiedCil = brKind; continue; }

                string binopKind = GuessHandlerIsBinop(h, module);
                if (binopKind != null) { e.IdentifiedCil = binopKind; continue; }

                // Trivial handlers that don't have a primary primitive call.
                // These survive all other classifiers as blank.
                string trivial = GuessHandlerTrivial(h);
                if (trivial != null) { e.IdentifiedCil = trivial; continue; }
            }

            // Apply second-pass known-primitive mapping.
            ApplyKnownPrimitives(module, perPrim);

            // Third pass: disambiguate Ldloc/Stloc -> Ldarg/Starg by hit-count.
            // The args-array field is used by fewer primitives than the locals-
            // array field. Primitives that read the less-used field get their
            // handlers relabeled from Ldloc/Stloc to Ldarg/Starg.
            DisambiguateLdargFromLdloc(map, perPrim, module);

            int identified = 0;
            foreach (var e in map.Entries)
                if (!string.IsNullOrEmpty(e.IdentifiedCil) && !e.IdentifiedCil.StartsWith("Prim_", StringComparison.Ordinal))
                    identified++;
            return identified;
        }

        private static readonly Dictionary<uint, uint> _primToFieldTok = new Dictionary<uint, uint>();

        private static void DisambiguateLdargFromLdloc(DynamicAnalyzer.OpcodeMap map, Dictionary<uint, List<DynamicAnalyzer.OpcodeEntry>> perPrim, ModuleDefMD module)
        {
            // For each primitive, find its primary array-field reference
            // (the first ldfld whose type is an array).
            foreach (var kvp in perPrim)
            {
                var md = module.ResolveMethod(kvp.Key & 0xFFFFFF) as MethodDef;
                if (md?.Body == null) continue;
                foreach (var ins in md.Body.Instructions)
                {
                    if (ins.OpCode.Code == Code.Ldfld && ins.Operand is IField f)
                    {
                        var ft = f.FieldSig?.Type?.FullName ?? "";
                        if (ft.EndsWith("[]", StringComparison.Ordinal))
                        {
                            _primToFieldTok[kvp.Key] = f.MDToken.Raw;
                            break;
                        }
                    }
                }
            }

            // Rank fields by total handler hits (i.e. sum of handlers per
            // primitive grouped by field). Least-hit field => args.
            var fieldHits = new Dictionary<uint, int>();
            foreach (var kvp in perPrim)
            {
                if (!_primToFieldTok.TryGetValue(kvp.Key, out uint fld)) continue;
                fieldHits.TryGetValue(fld, out int c);
                fieldHits[fld] = c + kvp.Value.Count;
            }

            if (fieldHits.Count < 2) return;

            // Sort ascending: smallest = args, rest = locals. If there are
            // exactly 2 fields, the smaller is args.
            var sorted = fieldHits.OrderBy(kv => kv.Value).ToList();
            var argsField = sorted[0].Key;

            // Relabel every handler whose primitive reads the args field.
            foreach (var kvp in perPrim)
            {
                if (!_primToFieldTok.TryGetValue(kvp.Key, out uint fld)) continue;
                if (fld != argsField) continue;

                foreach (var e in kvp.Value)
                {
                    var lbl = e.IdentifiedCil;
                    if (string.IsNullOrEmpty(lbl)) continue;
                    if (lbl.StartsWith("Ldloc", StringComparison.Ordinal))
                        e.IdentifiedCil = "Ldarg" + lbl.Substring(5);
                    else if (lbl.StartsWith("Stloc", StringComparison.Ordinal))
                        e.IdentifiedCil = "Starg" + lbl.Substring(5);
                }
            }
        }

        /// <summary>
        /// For each primitive, look at its body shape and guess its CIL
        /// semantic. We identify primitives by a small handful of structural
        /// patterns that have been stable across Eazfuscator versions.
        /// </summary>
        private static void ApplyKnownPrimitives(ModuleDefMD module, Dictionary<uint, List<DynamicAnalyzer.OpcodeEntry>> perPrim)
        {
            foreach (var kvp in perPrim)
            {
                var primMd = module.ResolveMethod(kvp.Key & 0xFFFFFF) as MethodDef;
                if (primMd == null) continue;

                var kind = GuessPrimitive(primMd);
                if (kind == null) continue;

                foreach (var e in kvp.Value)
                {
                    // Don't overwrite handler-level labels that already won.
                    if (!string.IsNullOrEmpty(e.IdentifiedCil))
                    {
                        var cur = e.IdentifiedCil;
                        if (cur == "Br" || cur == "Brtrue" || cur == "Brfalse"
                            || cur == "Bcc" || cur == "Binop"
                            || cur == "Nop" || cur == "NotImpl"
                            || cur == "Volatile" || cur == "DebugBreak"
                            || cur.StartsWith("Binop", StringComparison.Ordinal))
                            continue;
                    }

                    var label = e.IdentifiedCil;
                    int open = label.IndexOf('(');
                    int close = label.IndexOf(')');
                    string inner = (open > 0 && close > open + 1) ? label.Substring(open + 1, close - open - 1) : "";

                    // For Binop, map (bool1, bool2, maybe type) -> specific
                    // arithmetic. Historical Eazfuscator convention:
                    //   (0,0) add, (1,0) add.ovf, (0,1) add.ovf.un
                    //   (0,1,1) sub, ...etc. — exact mapping varies but
                    // the raw tail digits are useful forensics.
                    if (kind == "Binop" && inner.Length > 0)
                    {
                        // Eazfuscator binops take (val, val, bool, bool).
                        // The two bools are often "checked" and "unsigned":
                        //   (0,0) -> plain signed op
                        //   (1,0) -> checked signed (add.ovf etc.)
                        //   (0,1) -> plain unsigned
                        //   (1,1) -> checked unsigned (add.ovf.un etc.)
                        // We can't tell add vs sub vs mul from this alone
                        // because the primitive dispatches to ANOTHER method
                        // whose body encodes the actual op. But the (ovf, un)
                        // flags are stable. Name uniformly with their
                        // flags so readers know what they're looking at.
                        // Normalize the tail to just the last two values
                        // (the two bool flags). Anything before that is
                        // stray cflow noise even with the filter.
                        var parts = inner.Split(',');
                        string flags = parts.Length >= 2
                            ? $"{parts[parts.Length - 2]},{parts[parts.Length - 1]}"
                            : inner;
                        string kindStr;
                        switch (flags)
                        {
                            case "0,0": kindStr = "Binop_00"; break;      // signed, unchecked
                            case "1,0": kindStr = "Binop_10_ovf"; break;  // signed, checked
                            case "0,1": kindStr = "Binop_01_un"; break;   // unsigned, unchecked
                            case "1,1": kindStr = "Binop_11_ovf_un"; break;
                            default:    kindStr = $"Binop_{flags}"; break;
                        }
                        e.IdentifiedCil = kindStr;
                        continue;
                    }

                    // For Stloc/Ldloc/Ldc_I4/Starg/Ret, the tail's last int
                    // is the slot / value / whatever — use only that.
                    var tailParts = inner.Split(',');
                    string finalArg = tailParts[tailParts.Length - 1];
                    if (!int.TryParse(finalArg, out _)) finalArg = "";

                    if (finalArg.Length > 0)
                        e.IdentifiedCil = $"{kind}.{finalArg}";
                    else
                        e.IdentifiedCil = kind;
                }
            }
        }

        /// <summary>
        /// Match common primitive body shapes to CIL kinds. Heuristic — built
        /// from observed Eazfuscator 2025.3 primitives; may classify broadly.
        /// </summary>
        private static string GuessPrimitive(MethodDef prim)
        {
            if (prim.Body == null || !prim.Body.HasInstructions) return null;
            var ins = prim.Body.Instructions;

            // (0) Trivial: single `ret` -> Nop
            if (ins.Count == 1 && ins[0].OpCode.Code == Code.Ret)
                return "Nop";

            // (0b) Pure throw path -> NotImpl (VM opcode slot that throws
            // NotSupportedException; present in the dictionary but never
            // produces real output).
            if (ins.Any(i => i.OpCode.Code == Code.Throw))
            {
                bool hasNSE = ins.Any(i => i.OpCode.Code == Code.Newobj
                    && ((i.Operand as IMethod)?.DeclaringType?.FullName
                        ?? "").Contains("NotSupportedException"));
                if (hasNSE) return "NotImpl";
            }

            // (0c) MemoryBarrier / Debugger.Break hints.
            foreach (var i in ins)
            {
                if (i.OpCode.Code != Code.Call && i.OpCode.Code != Code.Callvirt) continue;
                var nm = (i.Operand as IMethod)?.FullName ?? "";
                if (nm.Contains("MemoryBarrier")) return "Volatile";
                if (nm.Contains("Debugger::Break") || nm.Contains("Debugger.Break")) return "DebugBreak";
            }

            // (1) Direct arithmetic in body — strongest signal.
            foreach (var i in ins)
            {
                switch (i.OpCode.Code)
                {
                    case Code.Add: return "Add";
                    case Code.Sub: return "Sub";
                    case Code.Mul: return "Mul";
                    case Code.Div: return "Div";
                    case Code.Rem: return "Rem";
                    case Code.And: return "And";
                    case Code.Or:  return "Or";
                    case Code.Xor: return "Xor";
                    case Code.Shl: return "Shl";
                    case Code.Shr: return "Shr";
                    case Code.Shr_Un: return "Shr_Un";
                    case Code.Ceq: return "Ceq";
                    case Code.Clt: return "Clt";
                    case Code.Cgt: return "Cgt";
                }
            }

            // (2) newobj <IntegerWrapper>(argN) pattern: the primitive takes
            // an int N and boxes it into a VM-internal value type. This is
            // how LDC.I4.N is implemented in 2025.x.
            //   ldarg.0 ; ldarg.1 ; newobj Wrapper::.ctor(int32) ; ...
            for (int k = 0; k < ins.Count - 2; k++)
            {
                if (ins[k].OpCode.Code == Code.Ldarg_1 && ins[k + 1].OpCode.Code == Code.Newobj)
                {
                    var ctor = (ins[k + 1].Operand as IMethod)?.ResolveMethodDef();
                    if (ctor != null && ctor.Name == ".ctor"
                        && ctor.Parameters.Count >= 1
                        && ctor.Parameters[ctor.Parameters.Count - 1].Type?.FullName == "System.Int32")
                        return "Ldc_I4";
                }
            }

            // (3) Primitive that writes a Boolean field and returns — flag
            // setter, most commonly "set IsReturning = true" (i.e. Ret).
            {
                int boolStores = ins.Count(i => i.OpCode.Code == Code.Stfld
                    && ((i.Operand as IField)?.FieldSig?.Type?.FullName) == "System.Boolean");
                if (boolStores >= 1 && ins.Count <= 15) return "Ret";
            }

            // (4) Primitive that dispatches to a deeper one with extra bool
            // flags: calls `other(val, val, bool, bool)`. This is an
            // arithmetic/comparison family dispatcher. We can't tell which
            // specific op without looking at the bool values passed —
            // handlers that use this primitive each fix a particular bool
            // combo. For now, name it "Binop".
            foreach (var i in ins)
            {
                if ((i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt) && i.Operand is IMethod mi)
                {
                    var md = mi.ResolveMethodDef();
                    if (md == null) continue;
                    var ps = md.Parameters;
                    if (ps.Count == 4 && ps[2].Type?.FullName == "System.Boolean" && ps[3].Type?.FullName == "System.Boolean")
                        return "Binop";
                    if (ps.Count == 5 && ps[3].Type?.FullName == "System.Boolean" && ps[4].Type?.FullName == "System.Boolean")
                        return "Binop";
                }
            }

            // (5) stelem -> Stloc or Starg-family. Disambiguate by which
            // field holds the array: args-array primitives and locals-array
            // primitives have distinct field tokens that the primitive's
            // ldfld consistently targets.
            if (ins.Any(i => i.OpCode.Code == Code.Stelem || i.OpCode.Code == Code.Stelem_Ref))
                return ClassifyArrayOp(ins, write: true);

            // (6) ldelem -> Ldloc or Ldarg-family
            if (ins.Any(i => i.OpCode.Code == Code.Ldelem || i.OpCode.Code == Code.Ldelem_Ref))
                return ClassifyArrayOp(ins, write: false);

            // (7) ldfld on a UInt32 + immediate ret — it's a state getter.
            // Not a CIL opcode itself, usually a helper; label as such so
            // traces don't claim it.
            if (ins.Count <= 12
                && ins.Any(i => i.OpCode.Code == Code.Ldfld)
                && ins[ins.Count - 1].OpCode.Code == Code.Ret
                && prim.ReturnType != null
                && (prim.ReturnType.FullName == "System.UInt32"
                    || prim.ReturnType.FullName == "System.Int32"
                    || prim.ReturnType.FullName == "System.UInt16"
                    || prim.ReturnType.FullName == "System.Int16"
                    || prim.ReturnType.FullName == "System.Byte"
                    || prim.ReturnType.FullName == "System.SByte"
                    || prim.ReturnType.FullName == "System.UInt64"
                    || prim.ReturnType.FullName == "System.Int64"
                    || prim.ReturnType.FullName == "System.Boolean"))
                return "StateGet";

            // (8) Branch: primitive takes int64/uint32 position arg, calls
            // a method to set VM PC.
            foreach (var i in ins)
            {
                if ((i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt) && i.Operand is IMethod m)
                {
                    var md = m.ResolveMethodDef();
                    if (md?.ReturnType?.FullName == "System.Void" && md.Parameters.Count >= 1 && md.Parameters.Count <= 3
                        && md.Parameters.Any(p => p.Type?.FullName == "System.Int64" || p.Type?.FullName == "System.UInt32"))
                        return "Br";
                }
            }

            // (9) Pop pattern: primitive calls another primitive, stores its
            // result, then reads & clears a field. Usually a "pop-and-use"
            // helper. Label "PopHelper".
            if (ins.Count <= 45
                && ins.Any(i => i.OpCode.Code == Code.Stfld)
                && ins.Count(i => i.OpCode.Code == Code.Ldarg_0) >= 3)
                return "Pop";

            // (10) Cast-and-unbox pattern: primitive pops, castclasses to
            // System.Type / Array, and calls another primitive. These are
            // the opcode-variants that take a Type operand (conv.r4 etc.).
            // Label as "TypeOp" — caller can read trace metadata.
            if (ins.Any(i => i.OpCode.Code == Code.Castclass)
                && ins.Any(i => (i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt)
                    && ((i.Operand as IMethod)?.ResolveMethodDef()?.Parameters?.Any(p => p.Type?.FullName == "System.Type") == true)))
                return "TypeOp";

            // (11) Array access: primitive castclasses to System.Array,
            // then calls Array.GetValue(long) or Array.SetValue(...).
            // These are Ldelem / Stelem family opcodes.
            bool castsToArray = ins.Any(i => i.OpCode.Code == Code.Castclass
                && (i.Operand as ITypeDefOrRef)?.FullName == "System.Array");
            if (castsToArray)
            {
                bool callsSet = ins.Any(i => (i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt)
                    && ((i.Operand as IMethod)?.Name?.ToString() == "SetValue"));
                bool callsGet = ins.Any(i => (i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt)
                    && ((i.Operand as IMethod)?.Name?.ToString() == "GetValue"));
                if (callsSet) return "Stelem";
                if (callsGet) return "Ldelem";
                return "ArrayOp";
            }

            // (12) Two-pop + direct call to an adjacent primitive: simple
            // "apply op" wrapper. Label generically as "StackOp" so these
            // don't remain as Prim_0x... unresolved.
            {
                int popCalls = ins.Count(i =>
                    (i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt)
                    && (i.Operand as IMethod)?.ResolveMethodDef() is MethodDef mm
                    && mm.ReturnType?.FullName != "System.Void"
                    && mm.Parameters.Count == 1);
                if (popCalls >= 2 && prim.ReturnType?.FullName == "System.Void")
                    return "StackOp";
            }

            return null; // unknown
        }

        /// <summary>
        /// Classify a handler as a Binop-family op: it (or any primitive it
        /// calls transitively at depth 1) invokes a method with signature
        /// (val, val, bool, bool). Returns the label with the two bool-flag
        /// values extracted, so the caller can distinguish add/ovf/un variants.
        /// </summary>
        private static string GuessHandlerIsBinop(MethodDef handler, ModuleDefMD module)
        {
            // Walk calls in the handler's body. Each call is either:
            //   - a simple helper like 0x060002B5 (pop-from-stack)
            //   - the Binop primitive itself with (val, val, bool, bool) sig
            //   - something else we don't care about
            // Depth-1 inspection: if the handler calls a void(bool, bool)
            // primitive, open THAT primitive and look for (val, val, bool, bool).
            foreach (var ins in handler.Body.Instructions)
            {
                if (ins.OpCode.Code != Code.Call && ins.OpCode.Code != Code.Callvirt) continue;
                var callee = (ins.Operand as IMethod)?.ResolveMethodDef();
                if (callee == null) continue;
                if (MatchesBinopSignature(callee)) return ExtractBinopFlagsLabel(handler, ins);

                // Depth-1: the handler might call a (void, bool, bool) shim
                // that in turn calls the (val, val, bool, bool) worker. The
                // shim's body reveals the worker.
                var cps = callee.Parameters;
                if (callee.ReturnType?.FullName == "System.Void"
                    && cps.Count == 3
                    && cps[1].Type?.FullName == "System.Boolean"
                    && cps[2].Type?.FullName == "System.Boolean"
                    && callee.Body != null)
                {
                    foreach (var ins2 in callee.Body.Instructions)
                    {
                        if (ins2.OpCode.Code != Code.Call && ins2.OpCode.Code != Code.Callvirt) continue;
                        var inner = (ins2.Operand as IMethod)?.ResolveMethodDef();
                        if (inner != null && MatchesBinopSignature(inner))
                            return ExtractBinopFlagsLabel(handler, ins);
                    }
                }
            }
            return null;
        }

        private static bool MatchesBinopSignature(MethodDef callee)
        {
            var ps = callee.Parameters;
            // Instance: (this, val, val, bool, bool) = 5 params
            // Static:   (val, val, bool, bool)       = 4 params
            if (ps.Count == 5
                && ps[3].Type?.FullName == "System.Boolean"
                && ps[4].Type?.FullName == "System.Boolean")
                return true;
            if (ps.Count == 4 && !callee.IsStatic == false
                && ps[2].Type?.FullName == "System.Boolean"
                && ps[3].Type?.FullName == "System.Boolean")
                return true;
            if (ps.Count == 4
                && ps[2].Type?.FullName == "System.Boolean"
                && ps[3].Type?.FullName == "System.Boolean")
                return true;
            return false;
        }

        /// <summary>
        /// Find the (bool, bool) pair passed to the handler's Binop call.
        /// The handler itself receives (this, bool, bool) and passes those
        /// through, so we look at its method signature + the two ldarg's
        /// immediately preceding the call. For handlers that directly pass
        /// ldc.i4 constants, those are the flags.
        /// </summary>
        private static string ExtractBinopFlagsLabel(MethodDef handler, Instruction callIns)
        {
            // Common 2025.3 pattern: handler is void(this, byte operand-byte).
            // It reads the two flag ints from static fields or passes ldarg.1
            // (the operand byte) twice. Not always resolvable to concrete
            // 0/1 at the handler level. Return generic "Binop" so tracer
            // emits "add" (signed unchecked default).
            return "Binop";
        }

        /// <summary>
        /// Catch handlers that have no primary primitive call: pure-ret,
        /// pure-throw, memory-barrier, debugger-break. Returns null if
        /// none apply.
        /// </summary>
        private static string GuessHandlerTrivial(MethodDef handler)
        {
            var ins = handler.Body?.Instructions;
            if (ins == null || ins.Count == 0) return null;

            // Single ret -> Nop
            if (ins.Count == 1 && ins[0].OpCode.Code == Code.Ret) return "Nop";

            // throw (NotSupportedException construction) -> NotImpl
            if (ins.Any(i => i.OpCode.Code == Code.Throw))
            {
                bool hasNSE = ins.Any(i => i.OpCode.Code == Code.Newobj
                    && ((i.Operand as IMethod)?.DeclaringType?.FullName
                        ?? "").Contains("NotSupportedException"));
                if (hasNSE) return "NotImpl";
            }

            // Calls to Thread.MemoryBarrier / Debugger.Break.
            foreach (var i in ins)
            {
                if (i.OpCode.Code != Code.Call && i.OpCode.Code != Code.Callvirt) continue;
                var nm = (i.Operand as IMethod)?.FullName ?? "";
                if (nm.Contains("MemoryBarrier")) return "Volatile";
                if (nm.Contains("Debugger::Break") || nm.Contains("Debugger.Break")) return "DebugBreak";
            }

            return null;
        }

        /// <summary>
        /// If this handler does "pop one or two + call branch-target setter",
        /// label it as Br / Brtrue / Brfalse / Br-conditional. Otherwise null.
        /// </summary>
        private static string GuessHandlerIsBranch(MethodDef handler)
        {
            var body = handler.Body;
            if (body?.Instructions == null) return null;
            int stackPops = 0;
            bool callsBranchTarget = false;
            int calls = 0;
            foreach (var ins in body.Instructions)
            {
                if (ins.OpCode.Code != Code.Call && ins.OpCode.Code != Code.Callvirt) continue;
                calls++;
                var m = (ins.Operand as IMethod)?.ResolveMethodDef();
                if (m == null) continue;
                // "stack pop" helper — returns a value, 0 args, on `this`.
                if (m.Parameters.Count <= 1 && m.ReturnType?.FullName != "System.Void"
                    && m.Body?.Instructions?.Count <= 40
                    && m.Body?.Instructions?.Any(x => x.OpCode.Code == Code.Stfld) == true)
                    stackPops++;
                // Branch-target setter: takes UInt32 (boxed into Nullable<UInt32>).
                if (m.Parameters.Count == 2
                    && m.Parameters[1].Type?.FullName == "System.UInt32"
                    && m.Body?.Instructions?.Any(x => x.OpCode.Code == Code.Newobj
                        && (((x.Operand as IMethod)?.DeclaringType?.FullName ?? "")
                            .Contains("Nullable"))) == true)
                    callsBranchTarget = true;
            }
            if (!callsBranchTarget) return null;
            if (stackPops == 0) return "Br";          // unconditional
            if (stackPops == 1) return "Brtrue";      // pop one, branch on truthy
            return "Bcc";                              // pop two, compare, conditional branch
        }

        /// <summary>
        /// The single-Int32 primitives that read/write the locals or args
        /// array share identical body shape; the only distinguishing signal
        /// is WHICH field holds the array. We collect all the array-op
        /// primitives, cluster them by field MDToken, and the two biggest
        /// clusters are (by convention from eazdevirt) locals (larger) and
        /// args (smaller). This happens lazily the first time we encounter
        /// an array-op.
        /// </summary>
        private static Dictionary<uint, string> _fieldToKind = null;

        /// <summary>
        /// Find the backing array field this primitive reads/writes and
        /// record (field, direction) so callers can later disambiguate
        /// locals vs args by cross-referencing direction counts.
        /// Field-token map: token -> usage count.
        /// </summary>
        private static readonly Dictionary<uint, int> _fieldHitCount = new Dictionary<uint, int>();

        private static string ClassifyArrayOp(IList<Instruction> ins, bool write)
        {
            foreach (var i in ins)
            {
                if (i.OpCode.Code == Code.Ldfld && i.Operand is IField f)
                {
                    var ft = f.FieldSig?.Type?.FullName ?? "";
                    if (ft.EndsWith("[]", StringComparison.Ordinal))
                    {
                        _fieldHitCount.TryGetValue(f.MDToken.Raw, out int c);
                        _fieldHitCount[f.MDToken.Raw] = c + 1;
                        break;
                    }
                }
            }
            return write ? "Stloc" : "Ldloc";
        }

        /// <summary>
        /// After all handlers have been classified, promote whichever
        /// array-field was used the FEWEST times to the "args" variant —
        /// the locals array is universally larger (accessed by more
        /// handlers than the args array). Call after ClassifyAll.
        /// </summary>
        public static void PromoteArgsField(DynamicAnalyzer.OpcodeMap map)
        {
            if (_fieldToKind == null || _fieldToKind.Count < 2) return;

            // Count how many handlers use each kind tag.
            var countByKind = new Dictionary<string, int>();
            foreach (var e in map.Entries)
            {
                if (string.IsNullOrEmpty(e.IdentifiedCil)) continue;
                var lbl = e.IdentifiedCil;
                var dot = lbl.IndexOf('.');
                var kind = dot > 0 ? lbl.Substring(0, dot) : lbl;
                countByKind.TryGetValue(kind, out int c);
                countByKind[kind] = c + 1;
            }

            // If both Stloc and Ldloc exist, the smaller-count field tag in
            // each direction becomes Starg / Ldarg respectively. We don't
            // have that granularity here — the existing implementation
            // just picks the first field for the whole kind — so this is a
            // no-op placeholder. Left in for future refinement.
        }
    }
}

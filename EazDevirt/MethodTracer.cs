using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using HarmonyLib;

namespace eazdevirt
{
    /// <summary>
    /// Drives a virtualized method end-to-end (load assembly -> patch the VM
    /// opcode-reader -> invoke the stub -> stop patch) to produce a
    /// "virtual IL listing": the sequence of VM opcodes fetched by the
    /// dispatcher during execution, each mapped to its classifier label.
    ///
    /// Output is a dnSpy-readable .il-style text file that approximates the
    /// method's runtime behavior even when the VM's internal bytecode format
    /// can't be decoded offline.
    /// </summary>
    public static class MethodTracer
    {
        public static string[] DependencyProbePaths { get; set; } = Array.Empty<string>();
        public static int MaxIntReadsPerStub { get; set; } = 250000;
        public static int MaxStubMilliseconds { get; set; } = 15000;

        public sealed class TraceResult
        {
            public int StubToken;
            public List<TraceLine> Lines = new List<TraceLine>();
            public byte[] CapturedStreamBytes = Array.Empty<byte>();
            public List<IntReadEvent> RawIntReads = new List<IntReadEvent>();
            public uint? SelectedOpcodeReaderToken;
            public string SelectedOpcodeReaderName;
            public string ErrorMessage;
        }

        public sealed class TraceLine
        {
            public int Index;
            public int RawValue;
            public string Label;          // from classifier; may be "Prim_0x..." or "add" etc.
            public uint? HandlerToken;    // the delegate handler's MDToken if known
        }

        public sealed class IntReadEvent
        {
            public int Index;
            public int RawValue;
            public uint MethodToken;
            public string MethodName;
            public bool IsKnownOpcode;
            public long StreamPosBefore = -1;
            public long StreamPosAfter = -1;
        }

        /// <summary>
        /// Trace every method whose token appears in <paramref name="targets"/>.
        /// Returns one TraceResult per target. Requires the opcode map to
        /// have been built first (so we know the handler for each opcode ID).
        /// </summary>
        public static List<TraceResult> Trace(string assemblyPath, DynamicAnalyzer.OpcodeMap map, IEnumerable<uint> targets, IDictionary<uint, object[]> probeArgs = null)
        {
            var results = new List<TraceResult>();
            using var scope = BeginDependencyResolveScope(assemblyPath, DependencyProbePaths);

            Assembly asm;
            try { asm = Assembly.LoadFrom(assemblyPath); }
            catch (Exception ex)
            {
                results.Add(new TraceResult { ErrorMessage = "load failed: " + ex.Message });
                return results;
            }

            // Locate the opcode reader method (int-returning callvirt inside
            // the single-opcode dispatch method). We look for a method that
            // returns int and takes 0 params, on the same declaring type as
            // any stub's dispatcher. 2025.3 has this at token 0x06000137.
            var opcodeReader = FindOpcodeReader(asm, map);
            if (opcodeReader == null)
            {
                results.Add(new TraceResult { ErrorMessage = "opcode reader not found" });
                return results;
            }

            // Patch ALL int-returning no-arg candidates on the VM type. The
            // opcode reader is whichever fires most per invocation; others
            // contribute noise that we filter out later.
            var harmony = new Harmony("eazdevirt.method-tracer." + Guid.NewGuid().ToString("N"));
            var prefixMI = typeof(TracerHelpers).GetMethod(nameof(TracerHelpers.OpcodeReaderPrefix), BindingFlags.Public | BindingFlags.Static);
            var postfixMI = typeof(TracerHelpers).GetMethod(nameof(TracerHelpers.OpcodeReaderPostfix), BindingFlags.Public | BindingFlags.Static);
            var byteCapturePostfixMI = typeof(TracerHelpers).GetMethod(nameof(TracerHelpers.ByteArrayIntPostfix), BindingFlags.Public | BindingFlags.Static);
            var patched = new List<MethodBase>();
            try
            {
                // Primary candidate (smallest body). Almost always works.
                harmony.Patch(opcodeReader, prefix: new HarmonyMethod(prefixMI), postfix: new HarmonyMethod(postfixMI));
                patched.Add(opcodeReader);
            }
            catch (Exception ex)
            {
                // Fall through — secondary candidates below.
                Console.Error.WriteLine("primary opcode reader patch failed: " + ex.Message);
            }

            // The real opcode reader lives on an internal reader class that
            // the VM delegates to, not on the VM type itself. Scan ALL types
            // in the assembly for any no-arg int-returning instance method
            // whose declaring type is referenced by the VM type (either by
            // field or by containment).
            var vmType = opcodeReader.DeclaringType;
            var interestingTypes = new HashSet<Type> { vmType };
            foreach (var f in vmType.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
            {
                if (!f.FieldType.IsPrimitive && f.FieldType != typeof(string))
                    interestingTypes.Add(f.FieldType);
            }
            // Also include nested types
            foreach (var n in vmType.GetNestedTypes(BindingFlags.Public | BindingFlags.NonPublic))
                interestingTypes.Add(n);

            foreach (var t in interestingTypes)
            {
                if (t == null) continue;
                foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {
                    if (m.ReturnType != typeof(int)) continue;
                    if (m.GetParameters().Length != 0) continue;
                    if (m == opcodeReader) continue;
                    try
                    {
                        harmony.Patch(m, postfix: new HarmonyMethod(postfixMI));
                        patched.Add(m);
                    }
                    catch { /* skip */ }
                }
            }

            if (patched.Count == 0)
            {
                results.Add(new TraceResult { ErrorMessage = "no patchable opcode reader candidate" });
                return results;
            }

            // Capture bytes from any int-returning method that touches byte[].
            // This includes stream.Read and transform-style decrypt routines.
            foreach (var t in SafeGetTypes(asm))
            {
                if (t == null) continue;
                foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                {
                    if (m.ReturnType != typeof(int)) continue;
                    var ps = m.GetParameters();
                    if (ps.Length == 0) continue;
                    if (!ps.Any(p => p.ParameterType == typeof(byte[]))) continue;
                    try
                    {
                        harmony.Patch(m, postfix: new HarmonyMethod(byteCapturePostfixMI));
                        patched.Add(m);
                    }
                    catch { /* best-effort */ }
                }
            }

            try
            {
                foreach (var tok in targets)
                {
                    var buf = new List<int>();
                    DynamicAnalyzer.OpcodeTraceBuffer = buf;
                    TracerHelpers.ConfigureRunLimits(MaxIntReadsPerStub, MaxStubMilliseconds);
                    TracerHelpers.ResetStreamCapture();
                    TracerHelpers.ResetIntReadCapture();
                    object[] argv = null;
                    if (probeArgs != null && probeArgs.TryGetValue(tok, out var a)) argv = a;

                    var r = new TraceResult { StubToken = (int)tok };
                    try
                    {
                        DynamicAnalyzer.TraceMethod(asm, tok, argv);
                    }
                    catch (Exception ex)
                    {
                        r.ErrorMessage = "invoke failed: " + ex.Message;
                    }
                    if (string.IsNullOrWhiteSpace(r.ErrorMessage) &&
                        !string.IsNullOrWhiteSpace(DynamicAnalyzer.LastTraceError))
                    {
                        r.ErrorMessage = DynamicAnalyzer.LastTraceError;
                    }
                    var guardReason = TracerHelpers.GetLimitReason();
                    if (!string.IsNullOrWhiteSpace(guardReason))
                    {
                        r.ErrorMessage = string.IsNullOrWhiteSpace(r.ErrorMessage)
                            ? "trace guard: " + guardReason
                            : (r.ErrorMessage + " | trace guard: " + guardReason);
                    }

                    var reads = TracerHelpers.GetIntReadCapture();
                    foreach (var ev in reads)
                    {
                        r.RawIntReads.Add(new IntReadEvent
                        {
                            Index = ev.Index,
                            RawValue = ev.RawValue,
                            MethodToken = ev.MethodToken,
                            MethodName = ev.MethodName,
                            IsKnownOpcode = map[ev.RawValue]?.HandlerToken.HasValue == true,
                            StreamPosBefore = ev.StreamPosBefore,
                            StreamPosAfter = ev.StreamPosAfter
                        });
                    }

                    var selectedReaderToken = SelectOpcodeReader(reads, map, out var selectedReaderName);
                    r.SelectedOpcodeReaderToken = selectedReaderToken;
                    r.SelectedOpcodeReaderName = selectedReaderName;

                    var opcodeReads = selectedReaderToken.HasValue
                        ? reads.Where(e => e.MethodToken == selectedReaderToken.Value).ToList()
                        : reads;

                    for (int i = 0; i < opcodeReads.Count; i++)
                    {
                        var entry = map[opcodeReads[i].RawValue];
                        var line = new TraceLine
                        {
                            Index = i,
                            RawValue = opcodeReads[i].RawValue,
                            Label = entry?.IdentifiedCil,
                            HandlerToken = entry?.HandlerToken
                        };
                        r.Lines.Add(line);
                    }
                    r.CapturedStreamBytes = TracerHelpers.GetStreamCapture();
                    results.Add(r);
                }
            }
            finally
            {
                try { harmony.UnpatchAll(harmony.Id); } catch { }
            }

            return results;
        }

        private static IDisposable BeginDependencyResolveScope(string assemblyPath, IEnumerable<string> extraProbePaths)
        {
            var probeDirs = new List<string>();
            var primaryDir = Path.GetDirectoryName(assemblyPath);
            if (!string.IsNullOrWhiteSpace(primaryDir) && Directory.Exists(primaryDir))
                probeDirs.Add(primaryDir);
            if (extraProbePaths != null)
            {
                foreach (var p in extraProbePaths)
                {
                    if (string.IsNullOrWhiteSpace(p) || !Directory.Exists(p)) continue;
                    if (!probeDirs.Contains(p)) probeDirs.Add(p);
                    try
                    {
                        foreach (var d in Directory.GetDirectories(p, "*", SearchOption.AllDirectories))
                        {
                            if (!probeDirs.Contains(d)) probeDirs.Add(d);
                        }
                    }
                    catch { }
                }
            }

            ResolveEventHandler handler = (_, args) =>
            {
                try
                {
                    var simple = new AssemblyName(args.Name).Name + ".dll";
                    foreach (var dir in probeDirs)
                    {
                        var candidate = Path.Combine(dir, simple);
                        if (!File.Exists(candidate)) continue;
                        try { return Assembly.LoadFrom(candidate); }
                        catch { }
                    }
                }
                catch { }
                return null;
            };

            AppDomain.CurrentDomain.AssemblyResolve += handler;
            return new ResolveScope(() => AppDomain.CurrentDomain.AssemblyResolve -= handler);
        }

        private sealed class ResolveScope : IDisposable
        {
            private readonly Action _dispose;
            public ResolveScope(Action dispose) { _dispose = dispose; }
            public void Dispose() { _dispose(); }
        }

        public static void WriteTextDump(TraceResult tr, TextWriter w)
        {
            w.WriteLine($"// === Trace for stub 0x{tr.StubToken:X8} ===");
            w.WriteLine($"// {tr.Lines.Count} int reads captured, {tr.Lines.Count(l => l.HandlerToken.HasValue)} resolved as VM opcodes");
            w.WriteLine($"// stream bytes captured: {tr.CapturedStreamBytes?.Length ?? 0}");
            if (tr.SelectedOpcodeReaderToken.HasValue)
                w.WriteLine($"// selected opcode reader: 0x{tr.SelectedOpcodeReaderToken.Value:X8} ({tr.SelectedOpcodeReaderName})");
            if (tr.ErrorMessage != null) w.WriteLine("// error: " + tr.ErrorMessage);

            var real = tr.Lines.Where(l => l.HandlerToken.HasValue).ToList();
            w.WriteLine();
            w.WriteLine("// --- Filtered VM opcode dispatches (IL-style) ---");
            w.WriteLine($".method stub_0x{tr.StubToken:X8}");
            w.WriteLine("{");
            int idx = 0;
            foreach (var line in real)
            {
                var label = string.IsNullOrEmpty(line.Label) ? "<unresolved>" : line.Label;
                // Format as CIL-ish line. Distinguish classified vs unresolved.
                string displayOp;
                if (label.StartsWith("Prim_", StringComparison.Ordinal))
                    displayOp = $"// vm.dispatch {label}";
                else
                    displayOp = FormatIlLine(label);
                w.WriteLine($"    IL_{idx:X4}:  {displayOp,-32}  // op=0x{line.RawValue:X8}, handler=0x{line.HandlerToken.Value:X8}");
                idx++;
            }
            w.WriteLine("}");
            w.WriteLine();
            w.WriteLine("// --- Raw capture (includes operand reads from stream) ---");
            foreach (var line in tr.Lines)
            {
                var label = string.IsNullOrEmpty(line.Label) ? "<operand>" : line.Label;
                var handler = line.HandlerToken.HasValue ? $"h=0x{line.HandlerToken.Value:X8}" : "h=?";
                w.WriteLine($"  [{line.Index,3}] op=0x{line.RawValue:X8}  {handler}  {label}");
            }
            w.WriteLine();
            w.WriteLine("// --- Method-tagged int reads (all patched readers) ---");
            foreach (var ev in tr.RawIntReads)
            {
                var pos = ev.StreamPosBefore >= 0 || ev.StreamPosAfter >= 0
                    ? $" pos={ev.StreamPosBefore}->{ev.StreamPosAfter}"
                    : "";
                w.WriteLine($"  [{ev.Index,4}] m=0x{ev.MethodToken:X8} {ev.MethodName} -> 0x{ev.RawValue:X8}{pos} {(ev.IsKnownOpcode ? "[opcode]" : "")}");
            }
        }

        public static void WritePortableTraces(string outPath, IEnumerable<TraceResult> traces, string errorMessage = null)
        {
            using var sw = new StreamWriter(outPath, false, Encoding.UTF8);
            if (!string.IsNullOrWhiteSpace(errorMessage))
            {
                sw.WriteLine("ERROR\t" + EscapePortable(errorMessage));
                return;
            }

            sw.WriteLine("OK");
            if (traces == null) return;
            foreach (var tr in traces)
            {
                var selectedTok = tr.SelectedOpcodeReaderToken.HasValue
                    ? tr.SelectedOpcodeReaderToken.Value.ToString("X8")
                    : "";
                sw.WriteLine("R\t" +
                             tr.StubToken.ToString(CultureInfo.InvariantCulture) + "\t" +
                             selectedTok + "\t" +
                             EscapePortable(tr.SelectedOpcodeReaderName) + "\t" +
                             EscapePortable(tr.ErrorMessage));

                if (tr.Lines != null)
                {
                    foreach (var line in tr.Lines)
                    {
                        var handlerTok = line.HandlerToken.HasValue
                            ? line.HandlerToken.Value.ToString("X8")
                            : "";
                        sw.WriteLine("L\t" +
                                     line.Index.ToString(CultureInfo.InvariantCulture) + "\t" +
                                     line.RawValue.ToString(CultureInfo.InvariantCulture) + "\t" +
                                     EscapePortable(line.Label) + "\t" +
                                     handlerTok);
                    }
                }

                if (tr.RawIntReads != null)
                {
                    foreach (var ev in tr.RawIntReads)
                    {
                        sw.WriteLine("I\t" +
                                     ev.Index.ToString(CultureInfo.InvariantCulture) + "\t" +
                                     ev.RawValue.ToString(CultureInfo.InvariantCulture) + "\t" +
                                     ev.MethodToken.ToString("X8") + "\t" +
                                     EscapePortable(ev.MethodName) + "\t" +
                                     (ev.IsKnownOpcode ? "1" : "0") + "\t" +
                                     ev.StreamPosBefore.ToString(CultureInfo.InvariantCulture) + "\t" +
                                     ev.StreamPosAfter.ToString(CultureInfo.InvariantCulture));
                    }
                }

                var bytes = tr.CapturedStreamBytes ?? Array.Empty<byte>();
                sw.WriteLine("B\t" + Convert.ToBase64String(bytes));
                sw.WriteLine("E");
            }
        }

        public static (List<TraceResult> Traces, string ErrorMessage) ReadPortableTraces(string path)
        {
            var traces = new List<TraceResult>();
            if (!File.Exists(path))
                return (traces, "portable trace file not found");
            string[] lines;
            try { lines = File.ReadAllLines(path); }
            catch (Exception ex) { return (traces, "portable trace read failed: " + ex.Message); }
            if (lines.Length == 0) return (traces, "portable trace file is empty");

            if (lines[0].StartsWith("ERROR\t", StringComparison.Ordinal))
                return (traces, UnescapePortable(lines[0].Substring("ERROR\t".Length)));
            if (!lines[0].Equals("OK", StringComparison.Ordinal))
                return (traces, "portable trace header invalid");

            TraceResult cur = null;
            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;
                var tag = line[0];
                if (tag == 'R' && line.StartsWith("R\t", StringComparison.Ordinal))
                {
                    var p = line.Split(new[] { '\t' }, 5);
                    if (p.Length < 5) continue;
                    if (!int.TryParse(p[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var stubTok))
                        continue;
                    cur = new TraceResult { StubToken = stubTok };
                    if (!string.IsNullOrWhiteSpace(p[2]) &&
                        uint.TryParse(p[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var rtok))
                        cur.SelectedOpcodeReaderToken = rtok;
                    cur.SelectedOpcodeReaderName = UnescapePortable(p[3]);
                    cur.ErrorMessage = UnescapePortable(p[4]);
                    traces.Add(cur);
                    continue;
                }
                if (cur == null) continue;

                if (tag == 'L' && line.StartsWith("L\t", StringComparison.Ordinal))
                {
                    var p = line.Split(new[] { '\t' }, 5);
                    if (p.Length < 5) continue;
                    if (!int.TryParse(p[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx)) continue;
                    if (!int.TryParse(p[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var raw)) continue;
                    uint? ht = null;
                    if (!string.IsNullOrWhiteSpace(p[4]) &&
                        uint.TryParse(p[4], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hv))
                        ht = hv;
                    cur.Lines.Add(new TraceLine
                    {
                        Index = idx,
                        RawValue = raw,
                        Label = UnescapePortable(p[3]),
                        HandlerToken = ht
                    });
                    continue;
                }
                if (tag == 'I' && line.StartsWith("I\t", StringComparison.Ordinal))
                {
                    var p = line.Split(new[] { '\t' }, 8);
                    if (p.Length < 6) continue;
                    if (!int.TryParse(p[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx)) continue;
                    if (!int.TryParse(p[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var raw)) continue;
                    if (!uint.TryParse(p[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var mtok)) continue;
                    long before = -1, after = -1;
                    if (p.Length >= 8)
                    {
                        _ = long.TryParse(p[6], NumberStyles.Integer, CultureInfo.InvariantCulture, out before);
                        _ = long.TryParse(p[7], NumberStyles.Integer, CultureInfo.InvariantCulture, out after);
                    }
                    cur.RawIntReads.Add(new IntReadEvent
                    {
                        Index = idx,
                        RawValue = raw,
                        MethodToken = mtok,
                        MethodName = UnescapePortable(p[4]),
                        IsKnownOpcode = p[5] == "1",
                        StreamPosBefore = before,
                        StreamPosAfter = after
                    });
                    continue;
                }
                if (tag == 'B' && line.StartsWith("B\t", StringComparison.Ordinal))
                {
                    var payload = line.Length > 2 ? line.Substring(2) : "";
                    try { cur.CapturedStreamBytes = Convert.FromBase64String(payload); }
                    catch { cur.CapturedStreamBytes = Array.Empty<byte>(); }
                    continue;
                }
                if (tag == 'E' && line.Equals("E", StringComparison.Ordinal))
                {
                    cur = null;
                }
            }

            return (traces, null);
        }

        private static string EscapePortable(string s) =>
            string.IsNullOrEmpty(s) ? "" : Uri.EscapeDataString(s);

        private static string UnescapePortable(string s) =>
            string.IsNullOrEmpty(s) ? "" : Uri.UnescapeDataString(s);

        /// <summary>
        /// Convert a classifier label like "Ldloc.0", "Stloc.2", "Ret.5"
        /// into an IL-like instruction line. For "Binop.0" we keep it
        /// raw since the exact arithmetic kind isn't resolvable yet.
        /// </summary>
        private static string FormatIlLine(string label)
        {
            if (label == null) return "nop";
            var dot = label.IndexOf('.');
            string op = dot > 0 ? label.Substring(0, dot).ToLowerInvariant() : label.ToLowerInvariant();
            string operand = dot > 0 ? label.Substring(dot + 1) : null;

            switch (op)
            {
                case "ldc_i4":
                    return operand != null ? $"ldc.i4 {operand}" : "ldc.i4";
                case "ldloc":
                    return operand != null ? $"ldloc.{operand}" : "ldloc";
                case "stloc":
                    return operand != null ? $"stloc.{operand}" : "stloc";
                case "ldarg":
                    return operand != null ? $"ldarg.{operand}" : "ldarg";
                case "starg":
                    return operand != null ? $"starg.{operand}" : "starg";
                case "ret":
                    return "ret";
                case "br":
                case "br_family":
                    return "br <offset>";
                case "brtrue":
                    return "brtrue <offset>";
                case "brfalse":
                    return "brfalse <offset>";
                case "bcc":
                    return "/* conditional branch */ beq <offset>";
                case "ceq":  return "ceq";
                case "clt":  return "clt";
                case "cgt":  return "cgt";
                case "add":  return "add";
                case "sub":  return "sub";
                case "mul":  return "mul";
                case "div":  return "div";
                case "rem":  return "rem";
                case "and":  return "and";
                case "or":   return "or";
                case "xor":  return "xor";
                case "shl":  return "shl";
                case "shr":  return "shr";
                case "shr_un": return "shr.un";
                case "binop":
                case "binop_00":
                    return "/* binop(signed, unchecked) */ add";
                case "binop_10_ovf":
                    return "/* binop(signed, ovf) */ add.ovf";
                case "binop_01_un":
                    return "/* binop(unsigned, unchecked) */ add.un";
                case "binop_11_ovf_un":
                    return "/* binop(unsigned, ovf) */ add.ovf.un";
                case "pop":
                    return "pop";
                case "stateget":
                    return "// stateget (VM-internal, no CIL equivalent)";
                default:
                    return $"/* {label} */";
            }
        }

        private static MethodBase FindOpcodeReader(Assembly asm, DynamicAnalyzer.OpcodeMap map)
        {
            // The handlers' DeclaringType holds the VM state. The opcode
            // reader is a no-arg int-returning instance method on the SAME
            // type as any handler (they all share one type per VM).
            // Pick any handler's MethodInfo and use its DeclaringType.
            Type vmType = null;
            foreach (var e in map.Entries)
            {
                if (!e.HandlerToken.HasValue) continue;
                foreach (var t in SafeGetTypes(asm))
                {
                    foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                    {
                        if ((uint)m.MetadataToken == e.HandlerToken.Value)
                        {
                            vmType = m.DeclaringType;
                            goto found;
                        }
                    }
                }
            }
            found:
            if (vmType == null) return null;

            // Among that VM type's instance methods, find int (): no-args.
            // Multiple candidates are possible; prefer one with a small body
            // (simple getter-style read) and whose invocation count during
            // normal VM execution would be high (we can't measure here).
            MethodBase best = null;
            int bestSize = int.MaxValue;
            foreach (var m in vmType.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                if (m.ReturnType != typeof(int)) continue;
                if (m.GetParameters().Length != 0) continue;
                int size;
                try
                {
                    var b = m.GetMethodBody();
                    size = b?.GetILAsByteArray()?.Length ?? int.MaxValue;
                }
                catch { continue; }
                if (size < bestSize)
                {
                    best = m; bestSize = size;
                }
            }
            return best;
        }

        private static IEnumerable<Type> SafeGetTypes(Assembly asm)
        {
            try { return asm.GetTypes(); }
            catch (ReflectionTypeLoadException e) { return e.Types.Where(x => x != null); }
            catch { return Array.Empty<Type>(); }
        }

        private static uint? SelectOpcodeReader(IReadOnlyList<TracerHelpers.IntReadCaptureEntry> reads, DynamicAnalyzer.OpcodeMap map, out string methodName)
        {
            methodName = null;
            if (reads == null || reads.Count == 0) return null;

            var grouped = reads
                .GroupBy(r => r.MethodToken)
                .Select(g =>
                {
                    int total = g.Count();
                    int known = g.Count(e => map[e.RawValue]?.HandlerToken.HasValue == true);
                    double ratio = total > 0 ? (double)known / total : 0;
                    return new { Token = g.Key, Name = g.First().MethodName, Total = total, Known = known, Ratio = ratio };
                })
                .OrderByDescending(x => x.Known)
                .ThenByDescending(x => x.Ratio)
                .ThenByDescending(x => x.Total)
                .FirstOrDefault();

            if (grouped == null || grouped.Known == 0) return null;
            methodName = grouped.Name;
            return grouped.Token;
        }
    }

    internal static class TracerHelpers
    {
        private sealed class PendingRead
        {
            public uint MethodToken;
            public long StreamPosBefore;
        }

        public sealed class IntReadCaptureEntry
        {
            public int Index;
            public int RawValue;
            public uint MethodToken;
            public string MethodName;
            public long StreamPosBefore = -1;
            public long StreamPosAfter = -1;
        }

        private static readonly object Sync = new object();
        private static List<byte> _streamCapture = new List<byte>();
        private static List<IntReadCaptureEntry> _intReads = new List<IntReadCaptureEntry>();
        private static int _intReadSeq;
        private static int _maxIntReadsPerStub = 250000;
        private static int _maxStubMilliseconds = 15000;
        private static long _runStartTicks;
        private static string _limitReason;
        [ThreadStatic] private static Stack<PendingRead> _pendingReads;
        [ThreadStatic] private static int _posProbeCounter;

        public static void ConfigureRunLimits(int maxIntReadsPerStub, int maxStubMilliseconds)
        {
            _maxIntReadsPerStub = maxIntReadsPerStub > 0 ? maxIntReadsPerStub : 250000;
            _maxStubMilliseconds = maxStubMilliseconds > 0 ? maxStubMilliseconds : 15000;
            _runStartTicks = Stopwatch.GetTimestamp();
            _limitReason = null;
        }

        public static string GetLimitReason() => _limitReason;

        public static void ResetStreamCapture()
        {
            lock (Sync) _streamCapture = new List<byte>();
        }

        public static byte[] GetStreamCapture()
        {
            lock (Sync) return _streamCapture.ToArray();
        }

        public static void ResetIntReadCapture()
        {
            lock (Sync)
            {
                _intReads = new List<IntReadCaptureEntry>();
                _intReadSeq = 0;
            }
            _pendingReads = null;
            _posProbeCounter = 0;
            CallCount = 0;
        }

        public static List<IntReadCaptureEntry> GetIntReadCapture()
        {
            lock (Sync)
            {
                return new List<IntReadCaptureEntry>(_intReads);
            }
        }

        public static int CallCount;
        public static void OpcodeReaderPrefix(object __instance, MethodBase __originalMethod)
        {
            if (__originalMethod == null) return;
            var stack = _pendingReads ??= new Stack<PendingRead>();
            bool samplePos = ((++_posProbeCounter & 0x0F) == 0);
            stack.Push(new PendingRead
            {
                MethodToken = (uint)__originalMethod.MetadataToken,
                StreamPosBefore = samplePos ? TryGetStreamPosition(__instance, __originalMethod) : -1
            });
        }

        public static void OpcodeReaderPostfix(int __result, object __instance, MethodBase __originalMethod)
        {
            CallCount++;
            if (_maxIntReadsPerStub > 0 && CallCount >= _maxIntReadsPerStub)
            {
                _limitReason ??= $"max-int-reads reached ({CallCount}/{_maxIntReadsPerStub})";
                throw new InvalidOperationException(_limitReason);
            }
            if (_maxStubMilliseconds > 0 && (CallCount & 0xFF) == 0)
            {
                long elapsedTicks = Stopwatch.GetTimestamp() - _runStartTicks;
                long elapsedMs = elapsedTicks * 1000 / Stopwatch.Frequency;
                if (elapsedMs >= _maxStubMilliseconds)
                {
                    _limitReason ??= $"max-ms reached ({elapsedMs}/{_maxStubMilliseconds})";
                    throw new TimeoutException(_limitReason);
                }
            }
            var buf = DynamicAnalyzer.OpcodeTraceBuffer;
            if (buf != null) buf.Add(__result);

            if (__originalMethod == null) return;
            long before = -1;
            var stack = _pendingReads;
            if (stack != null && stack.Count > 0)
            {
                var pending = stack.Pop();
                before = pending.StreamPosBefore;
            }
            long after = before >= 0 ? TryGetStreamPosition(__instance, __originalMethod) : -1;
            lock (Sync)
            {
                _intReads.Add(new IntReadCaptureEntry
                {
                    Index = _intReadSeq++,
                    RawValue = __result,
                    MethodToken = (uint)__originalMethod.MetadataToken,
                    MethodName = $"{__originalMethod.DeclaringType?.FullName}::{__originalMethod.Name}",
                    StreamPosBefore = before,
                    StreamPosAfter = after
                });
            }
        }

        private static long TryGetStreamPosition(object instance, MethodBase method)
        {
            long pos = TryGetStreamPositionInObject(instance, 2);
            if (pos >= 0) return pos;
            if (method?.DeclaringType != null)
            {
                try
                {
                    const BindingFlags sf = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;
                    foreach (var f in method.DeclaringType.GetFields(sf))
                    {
                        if (f.GetValue(null) is object candidate)
                        {
                            pos = TryGetStreamPositionInObject(candidate, 2);
                            if (pos >= 0) return pos;
                        }
                    }
                }
                catch { }
            }
            return -1;
        }

        private static long TryGetStreamPositionInObject(object instance, int depth)
        {
            if (instance == null || depth < 0) return -1;
            try
            {
                var t = instance.GetType();
                const BindingFlags bf = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance;

                foreach (var f in t.GetFields(bf))
                {
                    var ft = f.FieldType;
                    if (typeof(Stream).IsAssignableFrom(ft))
                    {
                        if (f.GetValue(instance) is Stream s) return s.CanSeek ? s.Position : -1;
                        continue;
                    }
                    if (typeof(BinaryReader).IsAssignableFrom(ft))
                    {
                        if (f.GetValue(instance) is BinaryReader br && br.BaseStream != null && br.BaseStream.CanSeek)
                            return br.BaseStream.Position;
                        continue;
                    }

                    if (!ft.IsPrimitive && ft != typeof(string) && !ft.IsEnum && depth > 0)
                    {
                        var nested = f.GetValue(instance);
                        if (nested != null && !ReferenceEquals(nested, instance))
                        {
                            var nestedPos = TryGetStreamPositionInObject(nested, depth - 1);
                            if (nestedPos >= 0) return nestedPos;
                        }
                    }
                }

            }
            catch { }
            return -1;
        }

        public static void ByteArrayIntPostfix(object[] __args, int __result)
        {
            if (__args == null || __result <= 0) return;

            byte[] chosen = null;
            int chosenOffset = 0;
            int chosenCount = 0;

            for (int i = 0; i < __args.Length; i++)
            {
                if (!(__args[i] is byte[] buf) || buf.Length == 0) continue;
                int off = 0;
                if (i + 1 < __args.Length && __args[i + 1] is int oi) off = oi;
                if (off < 0 || off >= buf.Length) continue;
                int count = Math.Min(__result, buf.Length - off);
                if (count <= 0) continue;
                if (count > chosenCount)
                {
                    chosen = buf;
                    chosenOffset = off;
                    chosenCount = count;
                }
            }

            if (chosen == null || chosenCount <= 0) return;

            lock (Sync)
            {
                // Guard against runaway captures if a sample loops forever.
                const int maxCaptureBytes = 4 * 1024 * 1024;
                int room = maxCaptureBytes - _streamCapture.Count;
                if (room <= 0) return;
                if (chosenCount > room) chosenCount = room;
                for (int i = 0; i < chosenCount; i++) _streamCapture.Add(chosen[chosenOffset + i]);
            }
        }
    }
}

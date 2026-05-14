using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using CommandLine;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using EazFixer.Processors;

namespace EazFixer
{
    internal class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                Parser.Default.ParseArguments<Options>(args)
                    .WithParsed(handleOptions)
                    .WithNotParsed(handleParsingError);

                if (Flags.WorkerBuildMap)
                    return RunMapWorkerMode();
                if (Flags.WorkerTrace)
                    return RunTraceWorkerMode();

                if (TryPreloadProbeDependency("Gapotchenko.FX.dll", out var preloadPath))
                    Console.WriteLine("Preloaded dependency: " + preloadPath);

                // Order is important. Run Devirtualizer before reflection-based
                // processors so a failed target <Module> initializer does not
                // poison the AppDomain before the VM map is captured.
                ProcessorBase[] processors = Flags.TraceOnly
                    ? Array.Empty<ProcessorBase>()
                    : new ProcessorBase[] {new Devirtualizer(), new StringFixer(), new ResourceResolver(), new Processors.AssemblyResolver()};

                // Add LicensePatcher when requested
                if (Flags.StripLicenseTelemetry || Flags.PatchEazfuscator || Flags.AnalyzeLicense)
                {
                    var oldList = processors;
                    processors = new ProcessorBase[oldList.Length + 1];
                    Array.Copy(oldList, processors, oldList.Length);
                    processors[oldList.Length] = new Processors.LicensePatcher();
                }
                var ctx = new EazContext(!string.IsNullOrEmpty(Flags.InFile) ? Flags.InFile : throw new Exception("Filepath not defined!"),
                    processors);

                Console.WriteLine("Executing memory patches...");
                StacktracePatcher.Patch();

                Console.WriteLine("Initializing modules...");
                foreach (ProcessorBase proc in ctx)
                    proc.Initialize(ctx);

                Console.WriteLine("Processing...");
                foreach (ProcessorBase proc in ctx.Where(a => a.Initialized))
                    proc.Process();

                Console.WriteLine("Cleanup...");
                foreach (ProcessorBase proc in ctx.Where(a => a.Processed && !(a is Devirtualizer)))
                    proc.Cleanup();
                foreach (ProcessorBase proc in ctx.Where(a => a.Processed && a is Devirtualizer))
                    proc.Cleanup();

                //write success/failure
                Console.WriteLine();
                Console.WriteLine("Applied patches:");
                var cc = Console.ForegroundColor;
                foreach (ProcessorBase p in ctx)
                {
                    Console.Write(p.GetType().Name + ": ");

                    if (p.CleanedUp)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Success");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Failed ({p.ErrorMessage})");
                    }

                    Console.ForegroundColor = cc;
                }

                Console.WriteLine();

                if (Flags.DeobCflow)
                {
                    Console.WriteLine();
                    Console.WriteLine("Running control-flow deobfuscator...");
                    var cfr = global::eazdevirt.ControlFlowDeob.Run((ModuleDefMD)ctx.Module);
                    Console.WriteLine("  touched {0} methods, {1} transforms total",
                        cfr.MethodsTouched, cfr.TotalTransforms);
                    if (cfr.MethodsSkipped > 0)
                        Console.WriteLine("  skipped {0} methods (errors)", cfr.MethodsSkipped);
                }

                if (Flags.CleanNames)
                {
                    Console.WriteLine();
                    Console.WriteLine("Cleaning unreadable names for dnSpy...");
                    var nr = DnSpyCleanup.Run(ctx.Module);
                    Console.WriteLine(
                        "  renamed {0} identifiers (types={1}, methods={2}, fields={3}, props={4}, events={5}, generics={6})",
                        nr.Total,
                        nr.TypesRenamed,
                        nr.MethodsRenamed,
                        nr.FieldsRenamed,
                        nr.PropertiesRenamed,
                        nr.EventsRenamed,
                        nr.GenericParametersRenamed);
                    if (nr.Total > 0 && Flags.PreserveAll)
                    {
                        Flags.PreserveAll = false;
                        Console.WriteLine("  disabled metadata token preservation after renaming identifiers");
                    }
                }

                if (Flags.PatchSpecs.Count > 0)
                {
                    Console.WriteLine();
                    Console.WriteLine("Applying return-patches:");
                    ReturnPatcher.ApplyAll((ModuleDefMD)ctx.Module, Flags.PatchSpecs);
                }

                if (Flags.TraceAllVmStubs)
                {
                    Console.WriteLine();
                    Console.WriteLine("Auto-detecting all VM stubs for tracing...");
                    var detect = new global::eazdevirt.DevirtualizeResult();
                    global::eazdevirt.PublicApi.DetectVirtualizedStubs((ModuleDefMD)ctx.Module, detect);
                    foreach (var s in detect.DetectedStubs)
                    {
                        if (!Flags.TraceMethodTokens.Contains(s.Token))
                            Flags.TraceMethodTokens.Add(s.Token);
                    }
                    int inferred = InferTraceArgsFromCallSites((ModuleDefMD)ctx.Module);
                    int skippedParamNoArgs = 0;
                    foreach (var tok in Flags.TraceMethodTokens.ToArray())
                    {
                        if (Flags.TraceMethodArgs.ContainsKey(tok))
                            continue;
                        if (!(((ModuleDefMD)ctx.Module).ResolveToken(tok) is MethodDef md) || md.MethodSig == null)
                            continue;
                        if (md.MethodSig.Params.Count <= 0)
                            continue;
                        Flags.TraceMethodTokens.Remove(tok);
                        skippedParamNoArgs++;
                    }
                    Console.WriteLine("  selected {0} stubs", Flags.TraceMethodTokens.Count);
                    if (inferred > 0)
                        Console.WriteLine("  inferred probe args for {0} stubs", inferred);
                    if (skippedParamNoArgs > 0)
                        Console.WriteLine("  skipped {0} parameterized stubs without probe args", skippedParamNoArgs);
                }

                if (Flags.TraceMethodTokens.Count > 0)
                {
                    Console.WriteLine();
                    Console.WriteLine("Tracing VM'd methods via in-process execution...");
                    IList<global::eazdevirt.MethodTracer.TraceResult> traces;
                    try
                    {
                        traces = Flags.TraceIsolated
                            ? TraceViaWorker()
                            : TraceInProcess((ModuleDefMD)ctx.Module);
                    }
                    catch (FileNotFoundException fnf)
                    {
                        Console.WriteLine("  trace failed: missing dependency during in-process load");
                        Console.WriteLine("    " + FlattenExceptionMessage(fnf));
                        Console.WriteLine("    hint: copy required dependency DLLs next to target module");
                        traces = Array.Empty<global::eazdevirt.MethodTracer.TraceResult>();
                    }
                    catch (Exception tex)
                    {
                        Console.WriteLine("  trace failed: " + FlattenExceptionMessage(tex));
                        traces = Array.Empty<global::eazdevirt.MethodTracer.TraceResult>();
                    }

                    foreach (var tr in traces)
                    {
                        var dir = Path.GetDirectoryName(Flags.OutFile) ?? "";
                        var baseName = Path.GetFileNameWithoutExtension(Flags.OutFile);
                        var tracePath = Path.Combine(dir, $"{baseName}.trace.0x{tr.StubToken:X8}.txt");
                        var traceBinPath = Path.Combine(dir, $"{baseName}.trace.0x{tr.StubToken:X8}.bin");
                        using (var fs = File.CreateText(tracePath))
                            global::eazdevirt.MethodTracer.WriteTextDump(tr, fs);
                        try { File.WriteAllBytes(traceBinPath, tr.CapturedStreamBytes ?? Array.Empty<byte>()); } catch { }
                        Console.WriteLine("  traced 0x{0:X8}: {1} opcodes -> {2}", tr.StubToken, tr.Lines.Count, tracePath);
                        Console.WriteLine("    captured stream bytes: {0} -> {1}", tr.CapturedStreamBytes?.Length ?? 0, traceBinPath);

                        if (Flags.DevirtRewrite)
                        {
                            int classifiedOps = tr.Lines.Count(l => l.HandlerToken.HasValue && !string.IsNullOrEmpty(l.Label));
                            if (!string.IsNullOrWhiteSpace(tr.ErrorMessage) && classifiedOps == 0)
                            {
                                Console.WriteLine("    rewrite skipped: trace contains errors ({0})", tr.ErrorMessage);
                                continue;
                            }
                            if (!string.IsNullOrWhiteSpace(tr.ErrorMessage) && classifiedOps > 0)
                                Console.WriteLine("    rewrite warning: trace had runtime errors but captured classified ops ({0})", tr.ErrorMessage);
                            bool useLoopFolding = !Flags.NoDevirtFoldLoops || Flags.DevirtFoldLoops;
                            var rw = global::eazdevirt.DevirtWriter.Rewrite((dnlib.DotNet.ModuleDefMD)ctx.Module, (uint)tr.StubToken, tr, useLoopFolding);
                            if (rw.ErrorMessage != null)
                                Console.WriteLine("    rewrite FAILED: {0}", rw.ErrorMessage);
                            else
                            {
                                Console.WriteLine("    rewrote stub body: {0} ops, {1} locals ({2}; branches {3}/{4})",
                                    rw.OpsEmitted, rw.LocalsDeclared,
                                    rw.UsedStaticCfg ? "static-cfg" : "trace-unroll",
                                    rw.BranchesResolved, rw.BranchesTotal);
                                if (!string.IsNullOrEmpty(rw.RewriteNote))
                                    Console.WriteLine("      note: {0}", rw.RewriteNote);
                            }
                        }
                    }
                }

                if (Flags.DumpOpcodeMap)
                {
                    Console.WriteLine();
                    Console.WriteLine("Dumping VM opcode map via in-process execution...");
                    var csvPath = Path.Combine(
                        Path.GetDirectoryName(Flags.OutFile) ?? "",
                        Path.GetFileNameWithoutExtension(Flags.OutFile) + ".opcodes.csv");
                    var map = global::eazdevirt.DynamicAnalyzer.BuildOpcodeMap(Flags.InFile);
                    if (map.ErrorMessage != null)
                    {
                        Console.WriteLine("  opcode-map dump FAILED: " + map.ErrorMessage);
                    }
                    else
                    {
                        // Two-stage classification:
                        //  1. V1 detectors (2018 era) — catches only the handful
                        //     whose 2018 pattern survived into 2025.
                        //  2. 2025 fingerprint classifier — labels by primitive
                        //     MDToken + operand, then tries to guess the
                        //     primitive's CIL kind from its body shape.
                        try
                        {
                            var eazModule = new global::eazdevirt.EazModule((dnlib.DotNet.ModuleDefMD)ctx.Module);
                            var (total, v1id) = global::eazdevirt.DynamicAnalyzer.Classify(map, (dnlib.DotNet.ModuleDefMD)ctx.Module, eazModule);
                            var extra = global::eazdevirt.HandlerClassifier2025.ClassifyAll(map, (dnlib.DotNet.ModuleDefMD)ctx.Module);
                            Console.WriteLine("  identified: V1={0}, 2025-classifier={1}, total {2}", v1id, extra, total);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("  classification failed: " + ex.Message);
                        }
                        global::eazdevirt.DynamicAnalyzer.WriteCsv(map, csvPath);
                        Console.WriteLine("  wrote {0} opcode entries -> {1}", map.Entries.Count, csvPath);
                    }
                }

                Console.WriteLine("Writing new assembly...");
                // When patching Eazfuscator itself we must preserve all metadata RIDs so
                // the token-addressed patches land at the same addresses in the output file.
                var mdFlags = (Flags.PreserveAll || Flags.PatchEazfuscator) ? MetadataFlags.PreserveAll : 0;
                // KeepOldMaxStack: if cflow deob or devirt patched bodies, dnlib
                // can't always recompute max stack. Keep the original value
                // (potentially oversized) to avoid hard-failing the write.
                if (Flags.DeobCflow || Flags.DevirtRewrite || !Flags.NoDevirt || Flags.PatchSpecs.Count > 0 || Flags.PatchEazfuscator)
                    mdFlags |= MetadataFlags.KeepOldMaxStack;

                var writerOpts = new ModuleWriterOptions(ctx.Module) { MetadataOptions = new MetadataOptions(mdFlags) };

                // When patching Eazfuscator itself, just preserve the public key
                // identity. The strong name signature becomes invalid after IL
                // changes, so the user must also apply the config-based bypass
                // (<bypassTrustedAppStrongNames/> in eazfuscator.net.exe.config).
                if (Flags.PatchEazfuscator)
                {
                    Console.WriteLine("  preserving public key identity for patched output...");
                    Console.WriteLine("  NOTE: Add <bypassTrustedAppStrongNames enabled=\"true\" /> to");
                    Console.WriteLine("        eazfuscator.net.exe.config to skip signature verification.");
                }

                ctx.Module.Write(Flags.OutFile, writerOpts);

#if DEBUG
                return Exit("DONE", true);
#else
                return Exit("Done.");
#endif
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                if (Environment.UserInteractive && !Console.IsInputRedirected)
                    Console.ReadKey();
                return 1;
            }
        }

        private static int Exit(string reason, bool askForInput = false)
        {
            Console.WriteLine(reason);
            if (askForInput)
            {
                Console.Write("Press any key to exit... ");
                Console.ReadKey();
            }
            return 0;
        }

        private static void handleOptions(Options args)
        {
            Flags.InFile = Path.GetFullPath(args.InFile);
            Flags.KeepTypes = args.KeepTypes;
            Flags.VirtFix = args.VirtFix;
            Flags.PreserveAll = args.PreserveAll;
            Flags.NoDevirt = args.NoDevirt;
            Flags.TraceOnly = args.TraceOnly;
            Flags.KeepVmTypes = args.KeepVmTypes;
            Flags.DumpOpcodeMap = args.DumpOpcodeMap;
            Flags.DeobCflow = args.DeobCflow;
            Flags.CleanNames = args.CleanNames;
            Flags.DevirtRewrite = args.DevirtRewrite;
            Flags.DevirtFoldLoops = args.DevirtFoldLoops;
            Flags.NoDevirtFoldLoops = args.NoDevirtFoldLoops;
            Flags.TraceAllVmStubs = args.TraceAllVmStubs;
            Flags.TraceMaxIntReads = args.TraceMaxIntReads > 0 ? args.TraceMaxIntReads : 250000;
            Flags.TraceMaxMs = args.TraceMaxMs > 0 ? args.TraceMaxMs : 15000;
            Flags.TraceIsolated = args.TraceIsolated;
            Flags.TraceWorkerTimeoutMs = args.TraceWorkerTimeoutMs > 0 ? args.TraceWorkerTimeoutMs : 30000;
            Flags.MapPrimerTimeoutMs = args.MapPrimerTimeoutMs > 0 ? args.MapPrimerTimeoutMs : 3000;
            Flags.MapBuildTimeoutMs = args.MapBuildTimeoutMs > 0 ? args.MapBuildTimeoutMs : 15000;
            Flags.MapBuildIsolated = args.MapBuildIsolated;
            Flags.WorkerBuildMap = args.WorkerBuildMap;
            Flags.WorkerMapOut = args.WorkerMapOut;
            Flags.WorkerTrace = args.WorkerTrace;
            Flags.WorkerTraceOut = args.WorkerTraceOut;
            Flags.VmProfile = string.IsNullOrWhiteSpace(args.VmProfile)
                ? "eaz2025-default"
                : args.VmProfile.Trim().ToLowerInvariant();
            Flags.ProbeDependencyPaths.Clear();
            const string defaultEazComponentsPath = @"C:\Program Files (x86)\Gapotchenko\Eazfuscator.NET\Components";
            if (Directory.Exists(defaultEazComponentsPath))
            {
                Flags.ProbeDependencyPaths.Add(defaultEazComponentsPath);
                try
                {
                    foreach (var d in Directory.GetDirectories(defaultEazComponentsPath))
                    {
                        if (!Flags.ProbeDependencyPaths.Contains(d))
                            Flags.ProbeDependencyPaths.Add(d);
                    }
                }
                catch { }
            }
            if (args.ProbeDependencyPaths != null)
            {
                foreach (var p in args.ProbeDependencyPaths)
                {
                    if (!string.IsNullOrWhiteSpace(p))
                    {
                        var path = p.Trim();
                        if (!Flags.ProbeDependencyPaths.Contains(path))
                            Flags.ProbeDependencyPaths.Add(path);
                    }
                }
            }
            global::eazdevirt.DynamicAnalyzer.DependencyProbePaths = Flags.ProbeDependencyPaths.ToArray();
            global::eazdevirt.DynamicAnalyzer.PrimerTimeoutMs = Flags.MapPrimerTimeoutMs;
            global::eazdevirt.MethodTracer.DependencyProbePaths = Flags.ProbeDependencyPaths.ToArray();
            global::eazdevirt.MethodTracer.MaxIntReadsPerStub = Flags.TraceMaxIntReads;
            global::eazdevirt.MethodTracer.MaxStubMilliseconds = Flags.TraceMaxMs;
            global::eazdevirt.DevirtWriter.VmProfile = Flags.VmProfile;

            if (!string.IsNullOrWhiteSpace(args.TraceMethod))
            {
                // Split on ; first so we can carry "0xTOK:a1,a2" groups.
                // If no semicolon exists and the spec contains ':', treat it as a
                // single token-with-args entry so arg commas stay intact.
                // For old token-only lists like "0xA,0xB", still allow comma split.
                string raw = args.TraceMethod;
                string[] parts;
                if (raw.Contains(";"))
                    parts = raw.Split(';');
                else if (raw.Contains(":"))
                    parts = new[] { raw };
                else
                    parts = raw.Split(',');

                foreach (var partRaw in parts)
                {
                    if (string.IsNullOrWhiteSpace(partRaw)) continue;
                    var part = partRaw.Trim();

                    string tokStr; string argStr = null;
                    int colon = part.IndexOf(':');
                    if (colon > 0)
                    {
                        tokStr = part.Substring(0, colon).Trim();
                        argStr = part.Substring(colon + 1).Trim();
                    }
                    else tokStr = part;

                    uint t;
                    if (tokStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        t = Convert.ToUInt32(tokStr.Substring(2), 16);
                    else
                        t = Convert.ToUInt32(tokStr, 16);
                    Flags.TraceMethodTokens.Add(t);

                    if (!string.IsNullOrEmpty(argStr))
                    {
                        var argVals = new List<object>();
                        foreach (var aRaw in argStr.Split(','))
                        {
                            var a = aRaw.Trim();
                            if (a.Length == 0) continue;
                            int v;
                            if (a.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                v = Convert.ToInt32(a.Substring(2), 16);
                            else
                                v = int.Parse(a, System.Globalization.CultureInfo.InvariantCulture);
                            argVals.Add(v);
                        }
                        Flags.TraceMethodArgs[t] = argVals.ToArray();
                    }
                }
            }
            Flags.StrDecTok = new MDToken(Convert.ToUInt32(args.StrDecTok, 16));
            Flags.ResResolverTok = new MDToken(Convert.ToUInt32(args.ResResolverTok, 16));
            Flags.ResInitTok = new MDToken(Convert.ToUInt32(args.ResInitTok, 16));
            Flags.AsmResDecompressTok = new MDToken(Convert.ToUInt32(args.AsmResDecompressTok, 16));
            Flags.AsmResDecryptTok = new MDToken(Convert.ToUInt32(args.AsmResDecryptTok, 16));
            Flags.AsmResTypeTok = new MDToken(Convert.ToUInt32(args.AsmResTypeTok, 16));
            Flags.AsmResMoveNextTok = new MDToken(Convert.ToUInt32(args.AsmResMoveNextTok, 16));

            if (args.Patches != null)
            {
                foreach (var raw in args.Patches)
                {
                    if (string.IsNullOrWhiteSpace(raw)) continue;
                    var eq = raw.IndexOf('=');
                    if (eq < 0)
                        throw new FormatException($"--patch '{raw}': expected '<token>=<value-spec>'");
                    var tokStr = raw.Substring(0, eq).Trim();
                    var spec = raw.Substring(eq + 1).Trim();
                    uint tok;
                    if (tokStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        tok = Convert.ToUInt32(tokStr.Substring(2), 16);
                    else
                        tok = Convert.ToUInt32(tokStr, 16);
                    Flags.PatchSpecs.Add((tok, spec));
                }
            }

            if (args.EazfuscatorPatches != null)
            {
                foreach (var raw in args.EazfuscatorPatches)
                {
                    if (string.IsNullOrWhiteSpace(raw)) continue;
                    var eq = raw.IndexOf('=');
                    if (eq < 0)
                        throw new FormatException($"--eazfuscator-patch-table '{raw}': expected '<token>=<value-spec>'");
                    var tokStr = raw.Substring(0, eq).Trim();
                    var spec = raw.Substring(eq + 1).Trim();
                    uint tok;
                    if (tokStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        tok = Convert.ToUInt32(tokStr.Substring(2), 16);
                    else
                        tok = Convert.ToUInt32(tokStr, 16);
                    Flags.EazfuscatorPatches.Add((tok, spec));
                }
            }
            Flags.StripLicenseTelemetry = args.StripLicenseTelemetry;
            Flags.PatchEazfuscator = args.PatchEazfuscator;
            Flags.AnalyzeLicense = args.AnalyzeLicense;

            if (args.OutFile != default)
            {
                Flags.OutFile = Path.GetFullPath(args.OutFile);
                return;
            }

            // Determine the output path if not given
            Flags.OutFile = Path.Combine(Path.GetDirectoryName(Flags.InFile) ?? "", 
                Path.GetFileNameWithoutExtension(Flags.InFile) + "-eazfix" + Path.GetExtension(Flags.InFile));
        }
        private static void handleParsingError(IEnumerable<Error> obj)
        {
            throw new FormatException();
        }

        private static int InferTraceArgsFromCallSites(ModuleDefMD module)
        {
            int inferred = 0;
            foreach (var token in Flags.TraceMethodTokens.ToArray())
            {
                if (Flags.TraceMethodArgs.ContainsKey(token))
                    continue;
                if (!(module.ResolveToken(token) is MethodDef target) || target.MethodSig == null)
                    continue;

                int argc = target.MethodSig.Params.Count;
                if (argc <= 0)
                    continue;
                if (!target.MethodSig.Params.All(p => p.ElementType == ElementType.I4))
                    continue;

                if (!TryFindConstantCallArgs(module, target, argc, out var args))
                    continue;

                Flags.TraceMethodArgs[token] = args.Cast<object>().ToArray();
                inferred++;
            }

            return inferred;
        }

        private static bool TryFindConstantCallArgs(ModuleDefMD module, MethodDef target, int argc, out int[] args)
        {
            args = null;
            foreach (var type in module.GetTypes())
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                var ins = method.Body.Instructions;
                for (int i = 0; i < ins.Count; i++)
                {
                    var op = ins[i].OpCode.Code;
                    if (op != Code.Call && op != Code.Callvirt) continue;
                    if (!(ins[i].Operand is IMethod called)) continue;
                    if (called.MDToken.ToUInt32() != target.MDToken.ToUInt32()) continue;
                    if (i < argc) continue;

                    var tmp = new int[argc];
                    bool ok = true;
                    for (int a = 0; a < argc; a++)
                    {
                        if (!TryDecodeI4(ins[i - argc + a], out tmp[a]))
                        {
                            ok = false;
                            break;
                        }
                    }
                    if (!ok) continue;
                    args = tmp;
                    return true;
                }
            }
            return false;
        }

        private static bool TryDecodeI4(Instruction ins, out int value)
        {
            switch (ins.OpCode.Code)
            {
                case Code.Ldc_I4_M1: value = -1; return true;
                case Code.Ldc_I4_0: value = 0; return true;
                case Code.Ldc_I4_1: value = 1; return true;
                case Code.Ldc_I4_2: value = 2; return true;
                case Code.Ldc_I4_3: value = 3; return true;
                case Code.Ldc_I4_4: value = 4; return true;
                case Code.Ldc_I4_5: value = 5; return true;
                case Code.Ldc_I4_6: value = 6; return true;
                case Code.Ldc_I4_7: value = 7; return true;
                case Code.Ldc_I4_8: value = 8; return true;
                case Code.Ldc_I4_S: value = (sbyte)ins.Operand; return true;
                case Code.Ldc_I4: value = (int)ins.Operand; return true;
                default:
                    value = 0;
                    return false;
            }
        }

        private static global::eazdevirt.DynamicAnalyzer.OpcodeMap BuildOpcodeMapInProcess()
        {
            if (Flags.MapBuildTimeoutMs <= 0)
                return global::eazdevirt.DynamicAnalyzer.BuildOpcodeMap(Flags.InFile);

            var mapTask = Task.Run(() => global::eazdevirt.DynamicAnalyzer.BuildOpcodeMap(Flags.InFile));
            if (!mapTask.Wait(Flags.MapBuildTimeoutMs))
            {
                Console.WriteLine("  map build failed: timeout after {0}ms", Flags.MapBuildTimeoutMs);
                return null;
            }
            return mapTask.Result;
        }

        private static global::eazdevirt.DynamicAnalyzer.OpcodeMap BuildOpcodeMapIsolated()
        {
            string tempOut = Path.Combine(Path.GetTempPath(), "eazfix-map-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                var psi = CreateWorkerStartInfo(BuildWorkerMapArgs(tempOut));
                using var proc = Process.Start(psi);
                if (proc == null)
                    return global::eazdevirt.DynamicAnalyzer.CreateErrorMap("worker spawn failed");

                if (Flags.MapBuildTimeoutMs > 0 && !proc.WaitForExit(Flags.MapBuildTimeoutMs))
                {
                    try { proc.Kill(); } catch { }
                    return global::eazdevirt.DynamicAnalyzer.CreateErrorMap($"worker timeout after {Flags.MapBuildTimeoutMs}ms");
                }
                proc.WaitForExit();

                if (!File.Exists(tempOut))
                {
                    var stderr = proc.StandardError.ReadToEnd();
                    return global::eazdevirt.DynamicAnalyzer.CreateErrorMap(
                        $"worker did not produce map output (exit={proc.ExitCode})" +
                        (!string.IsNullOrWhiteSpace(stderr) ? $": {stderr.Trim()}" : ""));
                }

                var map = global::eazdevirt.DynamicAnalyzer.ReadPortableMap(tempOut);
                if (map == null)
                {
                    return global::eazdevirt.DynamicAnalyzer.CreateErrorMap("worker map parse failed");
                }
                return map;
            }
            catch (Exception ex)
            {
                return global::eazdevirt.DynamicAnalyzer.CreateErrorMap("isolated map build failed: " + ex.Message);
            }
            finally
            {
                try { if (File.Exists(tempOut)) File.Delete(tempOut); } catch { }
            }
        }

        private static IList<global::eazdevirt.MethodTracer.TraceResult> TraceInProcess(ModuleDefMD module)
        {
            var map = Flags.MapBuildIsolated
                ? BuildOpcodeMapIsolated()
                : BuildOpcodeMapInProcess();
            if (map == null)
                return Array.Empty<global::eazdevirt.MethodTracer.TraceResult>();
            if (map.ErrorMessage != null)
                throw new Exception("map build failed: " + map.ErrorMessage);

            try { global::eazdevirt.HandlerClassifier2025.ClassifyAll(map, module); } catch { }
            return global::eazdevirt.MethodTracer.Trace(Flags.InFile, map, Flags.TraceMethodTokens, Flags.TraceMethodArgs);
        }

        private static IList<global::eazdevirt.MethodTracer.TraceResult> TraceViaWorker()
        {
            var all = new List<global::eazdevirt.MethodTracer.TraceResult>();
            foreach (var tok in Flags.TraceMethodTokens.Distinct())
            {
                var tr = RunTraceWorkerForToken(tok, Flags.TraceWorkerTimeoutMs, Flags.TraceMaxMs, Flags.TraceMaxIntReads);
                if (ShouldRetryTraceWorkerToken(tr))
                {
                    int retryTraceMaxMs = Math.Min(15000, Math.Max(Flags.TraceMaxMs * 3, Flags.TraceMaxMs + 3000));
                    int retryMaxReads = Math.Max(Flags.TraceMaxIntReads, 150000);
                    int retryTimeout = Math.Min(30000, Math.Max(Flags.TraceWorkerTimeoutMs * 3, retryTraceMaxMs + 2000));
                    var retried = RunTraceWorkerForToken(tok, retryTimeout, retryTraceMaxMs, retryMaxReads);
                    if (!ShouldRetryTraceWorkerToken(retried))
                        tr = retried;
                }
                all.Add(tr);
            }
            return all;
        }

        private static global::eazdevirt.MethodTracer.TraceResult RunTraceWorkerForToken(uint tok, int timeoutMs, int traceMaxMs, int traceMaxReads)
        {
            string tempOut = Path.Combine(Path.GetTempPath(), "eazfix-trace-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                var psi = CreateWorkerStartInfo(BuildWorkerTraceArgs(tempOut, BuildTraceMethodSpecForToken(tok), traceMaxMs, traceMaxReads));
                using var proc = Process.Start(psi);
                if (proc == null)
                    throw new Exception("trace worker spawn failed");

                if (timeoutMs > 0 && !proc.WaitForExit(timeoutMs))
                {
                    try { proc.Kill(); } catch { }
                    throw new TimeoutException($"trace worker timeout after {timeoutMs}ms");
                }
                proc.WaitForExit();

                if (!File.Exists(tempOut))
                {
                    var stderr = proc.StandardError.ReadToEnd();
                    throw new Exception($"trace worker produced no output (exit={proc.ExitCode})" +
                                        (!string.IsNullOrWhiteSpace(stderr) ? $": {stderr.Trim()}" : ""));
                }

                var (traces, err) = global::eazdevirt.MethodTracer.ReadPortableTraces(tempOut);
                if (!string.IsNullOrWhiteSpace(err))
                    throw new Exception(err);
                if (traces.Count == 0)
                    throw new Exception("trace worker returned no traces");
                return traces[0];
            }
            catch (Exception ex)
            {
                return new global::eazdevirt.MethodTracer.TraceResult
                {
                    StubToken = (int)tok,
                    ErrorMessage = ex.Message
                };
            }
            finally
            {
                try { if (File.Exists(tempOut)) File.Delete(tempOut); } catch { }
            }
        }

        private static bool ShouldRetryTraceWorkerToken(global::eazdevirt.MethodTracer.TraceResult tr)
        {
            if (tr == null) return true;
            if (!string.IsNullOrWhiteSpace(tr.ErrorMessage)) return false;
            if (tr.Lines == null || tr.Lines.Count == 0) return true;
            int resolved = tr.Lines.Count(l => l.HandlerToken.HasValue);
            return resolved == 0;
        }

        private static string BuildWorkerMapArgs(string outPath)
        {
            var parts = new List<string>
            {
                "--file", QuoteArg(Flags.InFile),
                "--worker-build-map",
                "--worker-map-out", QuoteArg(outPath),
                "--map-primer-timeout-ms", Flags.MapPrimerTimeoutMs.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--map-build-timeout-ms", "0",
                "--map-build-isolated", "false"
            };
            if (!string.IsNullOrWhiteSpace(Flags.VmProfile))
                parts.Add("--vm-profile " + QuoteArg(Flags.VmProfile));
            if (Flags.ProbeDependencyPaths.Count > 0)
            {
                string joined = string.Join(";", Flags.ProbeDependencyPaths);
                parts.Add("--probe-dependency-paths " + QuoteArg(joined));
            }
            return string.Join(" ", parts);
        }

        private static string BuildWorkerTraceArgs(string outPath, string traceMethodSpec, int traceMaxMs, int traceMaxReads)
        {
            var parts = new List<string>
            {
                "--file", QuoteArg(Flags.InFile),
                "--worker-trace",
                "--worker-trace-out", QuoteArg(outPath),
                "--trace-method", QuoteArg(traceMethodSpec),
                "--trace-max-int-reads", traceMaxReads.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--trace-max-ms", traceMaxMs.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--map-primer-timeout-ms", Flags.MapPrimerTimeoutMs.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--map-build-timeout-ms", Flags.MapBuildTimeoutMs.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--map-build-isolated", "false",
                "--trace-isolated", "false"
            };
            if (!string.IsNullOrWhiteSpace(Flags.VmProfile))
                parts.Add("--vm-profile " + QuoteArg(Flags.VmProfile));
            if (Flags.ProbeDependencyPaths.Count > 0)
            {
                string joined = string.Join(";", Flags.ProbeDependencyPaths);
                parts.Add("--probe-dependency-paths " + QuoteArg(joined));
            }
            return string.Join(" ", parts);
        }

        private static string BuildTraceMethodSpecForToken(uint tok)
        {
            var tokenSpec = "0x" + tok.ToString("X8");
            if (!Flags.TraceMethodArgs.TryGetValue(tok, out var args) || args == null || args.Length == 0)
                return tokenSpec;

            var argParts = new List<string>();
            foreach (var a in args)
            {
                if (a == null) continue;
                if (a is int iv) argParts.Add(iv.ToString(System.Globalization.CultureInfo.InvariantCulture));
                else if (a is IConvertible cv)
                    argParts.Add(cv.ToInt32(System.Globalization.CultureInfo.InvariantCulture).ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            if (argParts.Count > 0) tokenSpec += ":" + string.Join(",", argParts);
            return tokenSpec;
        }

        private static int RunMapWorkerMode()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(Flags.WorkerMapOut))
                {
                    Console.Error.WriteLine("worker mode requires --worker-map-out");
                    return 2;
                }
                var map = global::eazdevirt.DynamicAnalyzer.BuildOpcodeMap(Flags.InFile);
                global::eazdevirt.DynamicAnalyzer.WritePortableMap(map, Flags.WorkerMapOut);
                return 0;
            }
            catch (Exception ex)
            {
                try
                {
                    var m = global::eazdevirt.DynamicAnalyzer.CreateErrorMap(ex.Message);
                    if (!string.IsNullOrWhiteSpace(Flags.WorkerMapOut))
                        global::eazdevirt.DynamicAnalyzer.WritePortableMap(m, Flags.WorkerMapOut);
                }
                catch { }
                return 1;
            }
        }

        private static int RunTraceWorkerMode()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(Flags.WorkerTraceOut))
                {
                    Console.Error.WriteLine("worker trace mode requires --worker-trace-out");
                    return 2;
                }

                var map = global::eazdevirt.DynamicAnalyzer.BuildOpcodeMap(Flags.InFile);
                if (map == null || map.ErrorMessage != null)
                {
                    var msg = map?.ErrorMessage ?? "map build failed";
                    global::eazdevirt.MethodTracer.WritePortableTraces(Flags.WorkerTraceOut,
                        Array.Empty<global::eazdevirt.MethodTracer.TraceResult>(),
                        "map build failed: " + msg);
                    return 1;
                }

                ModuleDefMD module = null;
                try { module = ModuleDefMD.Load(Flags.InFile); } catch { }
                if (module != null)
                {
                    try { global::eazdevirt.HandlerClassifier2025.ClassifyAll(map, module); } catch { }
                }

                var traces = global::eazdevirt.MethodTracer.Trace(Flags.InFile, map, Flags.TraceMethodTokens, Flags.TraceMethodArgs);
                global::eazdevirt.MethodTracer.WritePortableTraces(Flags.WorkerTraceOut, traces);
                return 0;
            }
            catch (Exception ex)
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(Flags.WorkerTraceOut))
                        global::eazdevirt.MethodTracer.WritePortableTraces(
                            Flags.WorkerTraceOut,
                            Array.Empty<global::eazdevirt.MethodTracer.TraceResult>(),
                            ex.Message);
                }
                catch { }
                return 1;
            }
        }

        private static string QuoteArg(string s)
        {
            if (s == null) return "\"\"";
            return "\"" + s.Replace("\"", "\\\"") + "\"";
        }

        private static ProcessStartInfo CreateWorkerStartInfo(string workerArgs)
        {
            var assemblyPath = Assembly.GetExecutingAssembly().Location;
            var exePath = Path.ChangeExtension(assemblyPath, ".exe");
            var currentProcess = GetCurrentProcessPath();

            string fileName;
            string arguments;
            if (File.Exists(exePath))
            {
                fileName = exePath;
                arguments = workerArgs;
            }
            else if (!string.IsNullOrWhiteSpace(currentProcess) &&
                     string.Equals(Path.GetFileNameWithoutExtension(currentProcess), "dotnet", StringComparison.OrdinalIgnoreCase))
            {
                fileName = currentProcess;
                arguments = QuoteArg(assemblyPath) + " " + workerArgs;
            }
            else
            {
                fileName = currentProcess ?? assemblyPath;
                arguments = string.Equals(fileName, assemblyPath, StringComparison.OrdinalIgnoreCase)
                    ? workerArgs
                    : QuoteArg(assemblyPath) + " " + workerArgs;
            }

            return new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
        }

        private static string GetCurrentProcessPath()
        {
#if NETCOREAPP
            return Environment.ProcessPath;
#else
            try { return Process.GetCurrentProcess().MainModule?.FileName; }
            catch { return null; }
#endif
        }

        private static string FlattenExceptionMessage(Exception ex)
        {
            if (ex == null) return "";
            var parts = new List<string>();
            var cur = ex;
            int guard = 0;
            while (cur != null && guard++ < 6)
            {
                if (!string.IsNullOrWhiteSpace(cur.Message))
                    parts.Add(cur.Message.Trim());
                cur = cur.InnerException;
            }
            return string.Join(" | ", parts.Distinct());
        }

        private static bool TryPreloadProbeDependency(string fileName, out string loadedFrom)
        {
            loadedFrom = null;
            if (string.IsNullOrWhiteSpace(fileName)) return false;
            foreach (var dir in Flags.ProbeDependencyPaths)
            {
                if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                    continue;
                var candidate = Path.Combine(dir, fileName);
                if (!File.Exists(candidate))
                    continue;
                try
                {
                    Assembly.LoadFrom(candidate);
                    loadedFrom = candidate;
                    return true;
                }
                catch
                {
                    // best-effort preload only
                }
            }
            return false;
        }
    }
}

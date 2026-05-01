using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using eazdevirt.Logging;

namespace eazdevirt
{
    public sealed class DevirtualizeResult
    {
        public int MethodsDetected { get; internal set; }
        public int MethodsDevirted { get; internal set; }
        public List<string> UnrecognizedOpcodes { get; } = new List<string>();
        public List<string> FailedMethods { get; } = new List<string>();
        /// <summary>
        /// VM-stub methods found (token + full name). Populated even when the
        /// full devirt pipeline can't run (e.g. on Eazfuscator versions whose
        /// crypto stream we don't yet recognize). Useful for "these methods
        /// need a working devirt" reporting.
        /// </summary>
        public List<DetectedStub> DetectedStubs { get; } = new List<DetectedStub>();

        /// <summary>
        /// For each unique embedded VM resource seen across stubs, the resource
        /// name mapped to raw encrypted bytes. Useful for offline analysis
        /// (feeding into a standalone decryptor once the 2025.x crypto shape
        /// is reverse-engineered).
        /// </summary>
        public Dictionary<string, byte[]> VmResources { get; } = new Dictionary<string, byte[]>();

        public string ErrorMessage { get; internal set; }
    }

    public sealed class DetectedStub
    {
        public uint Token { get; internal set; }
        public string FullName { get; internal set; }
        public string DeclaringType { get; internal set; }

        /// <summary>
        /// The 10-char position string Eazfuscator uses to locate this stub's
        /// bytecode inside the embedded resource. Null if not extractable.
        /// </summary>
        public string PositionString { get; internal set; }

        /// <summary>
        /// Name of the embedded resource containing encrypted bytecode for
        /// this stub. Null if not extractable.
        /// </summary>
        public string ResourceStringId { get; internal set; }

        /// <summary>
        /// Full name of the VM dispatcher method the stub calls, if known.
        /// </summary>
        public string DispatcherFullName { get; internal set; }

        /// <summary>
        /// Full name of the VM dispatcher's declaring type ("VType"). This is
        /// the top-level class that contains the VM's execution logic.
        /// </summary>
        public string VmTypeFullName { get; internal set; }

        /// <summary>
        /// MDToken of the VM dispatcher method, if known.
        /// </summary>
        public uint? DispatcherToken { get; internal set; }

        /// <summary>
        /// MDToken of the VM type, if known.
        /// </summary>
        public uint? VmTypeToken { get; internal set; }
    }

    public static class PublicApi
    {
        public static DevirtualizeResult Devirtualize(ModuleDefMD module, ILogger logger = null)
        {
            var result = new DevirtualizeResult();
            if (module == null)
            {
                result.ErrorMessage = "module is null";
                return result;
            }
            logger = logger ?? DummyLogger.NoThrowInstance;

            // Detect stubs first — independent from crypto, always useful.
            DetectVirtualizedStubs(module, result);

            // Pull the raw encrypted bytes of every VM resource a stub points at.
            // We can't decrypt without the 2025.x crypto, but the bytes
            // themselves are useful — they can be piped into a standalone
            // analyzer or dnSpy/reflection-based decryptor.
            foreach (var stub in result.DetectedStubs)
            {
                if (string.IsNullOrEmpty(stub.ResourceStringId)) continue;
                if (result.VmResources.ContainsKey(stub.ResourceStringId)) continue;
                var er = module.Resources.FindEmbeddedResource(stub.ResourceStringId);
                if (er == null) continue;
                try { result.VmResources[stub.ResourceStringId] = er.CreateReader().ToArray(); }
                catch { /* best-effort */ }
            }

            // Then attempt the full devirt pipeline. If the crypto stream
            // can't be recognized (common on Eazfuscator versions > 2020),
            // this fails but the DetectedStubs list still has useful output.
            try
            {
                var eazModule = new EazModule(module, logger);
                var devirt = new Devirtualizer(eazModule, logger);

                var seen = new HashSet<string>();
                var results = devirt.Devirtualize(attempt =>
                {
                    if (attempt.Successful) return;

                    var methodName = attempt.Method != null ? attempt.Method.FullName : "<unknown method>";
                    if (attempt.WasInstructionUnknown)
                    {
                        var code = attempt.Reader != null ? attempt.Reader.LastVirtualOpCode.ToString("X8") : "<null>";
                        var offset = attempt.Reader != null ? attempt.Reader.CurrentVirtualOffset : 0u;
                        result.FailedMethods.Add(string.Format("{0}: unknown virtual opcode 0x{1} @ 0x{2:X8}", methodName, code, offset));
                        if (seen.Add(code))
                            result.UnrecognizedOpcodes.Add(code);
                    }
                    else
                    {
                        var msg = attempt.Exception != null ? attempt.Exception.Message : "unknown error";
                        result.FailedMethods.Add(string.Format("{0}: {1}", methodName, msg));
                    }
                });

                result.MethodsDetected = results.MethodCount;
                result.MethodsDevirted = results.DevirtualizedCount;

                if (result.MethodsDevirted < result.MethodsDetected)
                    TryModernStaticDevirtualize(module, eazModule, result);
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                // MethodsDetected falls back to the standalone detection count
                // so that even when the pipeline can't run, callers see a
                // meaningful number of stubs.
                if (result.MethodsDetected == 0)
                    result.MethodsDetected = result.DetectedStubs.Count;
            }
            return result;
        }

        private static void TryModernStaticDevirtualize(ModuleDefMD module, EazModule eazModule, DevirtualizeResult result)
        {
            try
            {
                var stubs = eazModule.FindMethodStubs();
                if (stubs.Length == 0)
                    return;

                var location = module.Location;
                if (String.IsNullOrWhiteSpace(location))
                    return;

                var map = DynamicAnalyzer.BuildOpcodeMap(location);
                if (map == null || map.ErrorMessage != null)
                    return;

                try { HandlerClassifier2025.ClassifyAll(map, module); } catch { }

                var bytecodeByStub = new ModernStaticBytecodeExtractor(eazModule, stubs).Extract();
                var rewritten = 0;
                foreach (var stub in stubs)
                {
                    if (!bytecodeByStub.TryGetValue(stub.Method.MDToken.Raw, out var bytecode) || bytecode == null || bytecode.Length < 4)
                        continue;

                    var trace = BuildSyntheticStaticTrace(stub.Method.MDToken.Raw, bytecode, map);
                    var rw = DevirtWriter.Rewrite(module, stub.Method.MDToken.Raw, trace, true);
                    if (String.IsNullOrEmpty(rw.ErrorMessage))
                        rewritten++;
                }

                if (rewritten > result.MethodsDevirted)
                {
                    result.MethodsDevirted = rewritten;
                    result.FailedMethods.Clear();
                    result.UnrecognizedOpcodes.Clear();
                    result.ErrorMessage = null;
                }
            }
            catch (Exception ex)
            {
                if (String.IsNullOrEmpty(result.ErrorMessage))
                    result.ErrorMessage = "modern static fallback failed: " + ex.Message;
            }
        }

        private static MethodTracer.TraceResult BuildSyntheticStaticTrace(uint stubToken, byte[] bytecode, DynamicAnalyzer.OpcodeMap map)
        {
            var trace = new MethodTracer.TraceResult
            {
                StubToken = unchecked((int)stubToken),
                CapturedStreamBytes = bytecode,
                SelectedOpcodeReaderToken = 0x06002B68
            };

            var seenAt = 0;
            for (int i = 0; i + 3 < bytecode.Length; i += 4)
            {
                int raw = bytecode[i]
                          | (bytecode[i + 3] << 24)
                          | (bytecode[i + 1] << 16)
                          | (bytecode[i + 2] << 8);
                var entry = map[raw];
                if (entry == null || !entry.HandlerToken.HasValue || String.IsNullOrEmpty(entry.IdentifiedCil))
                    continue;

                trace.Lines.Add(new MethodTracer.TraceLine
                {
                    Index = seenAt++,
                    RawValue = raw,
                    HandlerToken = entry.HandlerToken,
                    Label = entry.IdentifiedCil
                });
            }

            return trace;
        }

        /// <summary>
        /// Standalone virtualized-stub detection that does not depend on the
        /// crypto stream or the opcode map. Uses the same IL-signature
        /// heuristic as <see cref="EazModule.IsMethodStub(MethodDef)"/> so it
        /// works on any Eazfuscator version that still emits the classic
        /// stub preamble (length-10 ldstr + dispatch call taking
        /// (Stream, String, Object[])).
        /// </summary>
        public static void DetectVirtualizedStubs(ModuleDefMD module, DevirtualizeResult result)
        {
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    var stub = TryExtractStubInfo(method, type);
                    if (stub != null) result.DetectedStubs.Add(stub);
                }
            }
        }

        private static DetectedStub TryExtractStubInfo(MethodDef method, TypeDef declaringType)
        {
            if (method == null || !method.HasBody || !method.Body.HasInstructions) return null;

            string positionString = null;
            MethodDef dispatcher = null;
            var instrs = method.Body.Instructions;

            // Scan for the dispatch call first (that's the strongest signal).
            for (int i = 0; i < instrs.Count; i++)
            {
                var instr = instrs[i];
                if (instr.OpCode.Code != Code.Call) continue;
                var callee = ResolveCalleeDef(instr.Operand);
                if (callee == null) continue;
                if (!LooksLikeDispatcher(callee)) continue;

                dispatcher = callee;

                // Position string is the last ldstr with length-10 operand
                // before the dispatch call.
                for (int j = i - 1; j >= 0; j--)
                {
                    if (instrs[j].OpCode.Code == Code.Ldstr
                        && instrs[j].Operand is string s
                        && s.Length == 10)
                    {
                        positionString = s;
                        break;
                    }
                }
                break;
            }

            if (dispatcher == null || positionString == null) return null;

            // Find the CreateStreamMethod — a Call target returning Stream
            // that appears before the dispatcher call in this stub.
            MethodDef createStream = null;
            foreach (var ins in instrs)
            {
                if (ins.OpCode.Code != Code.Call) continue;
                var callee = ResolveCalleeDef(ins.Operand);
                if (callee == null) continue;
                if (callee.ReturnType?.FullName == "System.IO.Stream")
                {
                    createStream = callee;
                    break;
                }
            }

            string resourceId = null;
            if (createStream != null && createStream.HasBody && createStream.Body.HasInstructions)
            {
                foreach (var ins in createStream.Body.Instructions)
                {
                    if (ins.OpCode.Code == Code.Ldstr && ins.Operand is string rs)
                    {
                        resourceId = rs;
                        break;
                    }
                }
            }

            var vmType = dispatcher.DeclaringType;

            return new DetectedStub
            {
                Token = method.MDToken.Raw,
                FullName = SafeName(method),
                DeclaringType = SafeTypeName(declaringType),
                PositionString = positionString,
                ResourceStringId = resourceId,
                DispatcherFullName = SafeName(dispatcher),
                DispatcherToken = dispatcher.MDToken.Raw,
                VmTypeFullName = vmType != null ? SafeTypeName(vmType) : null,
                VmTypeToken = vmType?.MDToken.Raw
            };
        }

        private static MethodDef ResolveCalleeDef(object operand)
        {
            if (operand is MethodDef md) return md;
            if (operand is IMethod m) return m.ResolveMethodDef();
            return null;
        }

        private static bool LooksLikeDispatcher(MethodDef callee)
        {
            var sig = callee.MethodSig;
            if (sig == null) return false;
            var parms = sig.Params;
            int count = parms?.Count ?? 0;
            // (Stream, String, Object[]) directly, OR prepended class-context arg,
            // OR 6/7-param generic-overload variants.
            if (count != 3 && count != 4 && count != 6 && count != 7) return false;
            int offset = (count == 4 || count == 7) ? 1 : 0;
            if (parms.Count < offset + 3) return false;
            return parms[offset].FullName == "System.IO.Stream"
                && parms[offset + 1].FullName == "System.String"
                && parms[offset + 2].FullName == "System.Object[]";
        }

        private static string SafeName(MethodDef m)
        {
            try { return m.FullName; }
            catch { return "<unprintable: 0x" + m.MDToken.Raw.ToString("X8") + ">"; }
        }

        private static string SafeTypeName(TypeDef t)
        {
            try { return t.FullName; }
            catch { return "<unprintable: 0x" + t.MDToken.Raw.ToString("X8") + ">"; }
        }
    }
}

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using dnlib.DotNet;

namespace eazdevirt
{
    /// <summary>
    /// Dynamic analysis: loads the target assembly into the current process,
    /// invokes a VM'd stub to trigger static cctor initialization, then
    /// reflects on the VM's opcode dispatch dictionary to produce a full
    /// opcode -> handler MDToken map.
    ///
    /// Requires in-process execution of the target, so the usual EazFixer
    /// security warning applies: only use on binaries you trust.
    /// </summary>
    public static class DynamicAnalyzer
    {
        public static string[] DependencyProbePaths { get; set; } = Array.Empty<string>();
        public static int PrimerTimeoutMs { get; set; } = 3000;

        public sealed class OpcodeEntry
        {
            public int OpcodeId { get; internal set; }
            public uint? HandlerToken { get; internal set; }
            public string HandlerName { get; internal set; }
            public string HandlerDeclaringType { get; internal set; }
            public string IdentifiedCil { get; internal set; }
        }

        public sealed class OpcodeMap
        {
            public List<OpcodeEntry> Entries { get; } = new List<OpcodeEntry>();
            public string ErrorMessage { get; internal set; }

            public OpcodeEntry this[int opcode] => Entries.FirstOrDefault(e => e.OpcodeId == opcode);
        }

        public static OpcodeMap CreateErrorMap(string message) => new OpcodeMap { ErrorMessage = message };
        public static string LastTraceError { get; private set; }

        /// <summary>
        /// Invoke a virtualized method by MDToken and capture the sequence
        /// of opcode ints fetched by the VM during its execution.
        ///
        /// The caller must have previously patched the opcode-reader method
        /// (usually a Harmony postfix on the int-returning reader inside the
        /// VM's single-opcode dispatcher). When that's in place this method
        /// just triggers execution; the patch fills the sequence list.
        /// </summary>
        public static List<int> TraceMethod(Assembly asm, uint targetToken, object[] invokeArgs)
        {
            LastTraceError = null;
            foreach (var t in asm.GetTypes())
            {
                foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {
                    if ((uint)m.MetadataToken != targetToken) continue;

                    object inst = null;
                    if (!m.IsStatic)
                    {
                        try { inst = Activator.CreateInstance(m.DeclaringType); }
                        catch
                        {
                            try { inst = FormatterServices.GetUninitializedObject(m.DeclaringType); }
                            catch (Exception iex)
                            {
                                LastTraceError = "instance creation failed: " + iex.Message;
                            }
                        }
                    }
                    var ps = m.GetParameters();
                    var argv = invokeArgs;
                    if (argv == null || argv.Length != ps.Length)
                    {
                        argv = new object[ps.Length];
                        for (int i = 0; i < ps.Length; i++)
                            argv[i] = ps[i].ParameterType.IsValueType ? Activator.CreateInstance(ps[i].ParameterType) : null;
                    }
                    try { m.Invoke(inst, argv); }
                    catch (Exception ex)
                    {
                        LastTraceError = ex.InnerException?.Message ?? ex.Message;
                        /* trace still may be partially populated */
                    }
                    return OpcodeTraceBuffer;
                }
            }
            LastTraceError = "target token not found";
            return new List<int>();
        }

        // Shared buffer the Harmony postfix writes into.
        public static List<int> OpcodeTraceBuffer { get; set; } = new List<int>();

        public static OpcodeMap BuildOpcodeMap(string assemblyPath)
        {
            var result = new OpcodeMap();
            using (var scope = BeginDependencyResolveScope(assemblyPath, DependencyProbePaths))
            {
                Assembly asm;
                try { asm = Assembly.LoadFrom(assemblyPath); }
                catch (Exception ex) { result.ErrorMessage = "load failed: " + ex.Message; return result; }

                // Prime the VM by invoking any stub (method with a length-10 ldstr).
                var primerMsg = RunPrimerWithTimeout(asm, out var primed);
                if (!primed)
                {
                    // Still worth checking — the dictionary may be eagerly
                    // initialized in a module cctor.
                }

                // Find the static Dictionary<int, X> with the most entries.
                IDictionary dict = null;
                foreach (var t in SafeGetTypes(asm))
                {
                    foreach (var f in SafeGetStaticFields(t))
                    {
                        var ft = f.FieldType;
                        if (!ft.IsGenericType || ft.GetGenericTypeDefinition() != typeof(Dictionary<,>)) continue;
                        if (ft.GetGenericArguments()[0] != typeof(int)) continue;
                        object v;
                        try { v = f.GetValue(null); }
                        catch { continue; }
                        if (v is IDictionary d && d.Count > 100 && (dict == null || d.Count > dict.Count))
                            dict = d;
                    }
                }

                if (dict == null)
                {
                    result.ErrorMessage = "no static Dictionary<int,*> with >100 entries found" +
                        (primerMsg != null ? " (primer: " + primerMsg + ")" : "");
                    return result;
                }

                var enumerator = dict.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    var entry = new OpcodeEntry { OpcodeId = (int)enumerator.Key };
                    var val = enumerator.Value;
                    if (val != null)
                    {
                        foreach (var f in val.GetType().GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
                        {
                            object inner;
                            try { inner = f.GetValue(val); }
                            catch { continue; }
                            if (inner is Delegate d)
                            {
                                entry.HandlerToken = (uint)d.Method.MetadataToken;
                                entry.HandlerName = d.Method.Name;
                                entry.HandlerDeclaringType = d.Method.DeclaringType?.FullName;
                                break;
                            }
                        }
                    }
                    result.Entries.Add(entry);
                }
            }
            return result;
        }

        private static string RunPrimerWithTimeout(Assembly asm, out bool primed)
        {
            primed = false;
            if (PrimerTimeoutMs <= 0)
            {
                primed = TryPrime(asm, out var directMsg);
                return directMsg;
            }

            try
            {
                var task = Task.Run(() =>
                {
                    bool ok = TryPrime(asm, out var msg);
                    return (ok, msg);
                });
                if (!task.Wait(PrimerTimeoutMs))
                    return $"timeout after {PrimerTimeoutMs}ms";
                primed = task.Result.ok;
                return task.Result.msg;
            }
            catch (Exception ex)
            {
                return "primer task failed: " + (ex.InnerException?.Message ?? ex.Message);
            }
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

        public static void WriteCsv(OpcodeMap map, string outPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("opcode,handler_mdtoken,handler_method,declaring_type,cil");
            foreach (var e in map.Entries)
            {
                var tok = e.HandlerToken.HasValue ? "0x" + e.HandlerToken.Value.ToString("X8") : "?";
                var name = e.HandlerName?.Replace("\"", "\"\"") ?? "?";
                var decl = e.HandlerDeclaringType?.Replace("\"", "\"\"") ?? "?";
                var cil = e.IdentifiedCil ?? "";
                sb.AppendLine($"0x{e.OpcodeId:X8},{tok},\"{name}\",\"{decl}\",{cil}");
            }
            File.WriteAllText(outPath, sb.ToString());
        }

        public static void WritePortableMap(OpcodeMap map, string outPath)
        {
            using var sw = new StreamWriter(outPath, false, Encoding.UTF8);
            if (!string.IsNullOrWhiteSpace(map?.ErrorMessage))
            {
                sw.WriteLine("ERROR\t" + EscapePortable(map.ErrorMessage));
                return;
            }

            sw.WriteLine("OK");
            if (map?.Entries == null) return;
            foreach (var e in map.Entries)
            {
                var tok = e.HandlerToken.HasValue ? e.HandlerToken.Value.ToString("X8") : "";
                sw.WriteLine(
                    e.OpcodeId.ToString(CultureInfo.InvariantCulture) + "\t" +
                    tok + "\t" +
                    EscapePortable(e.HandlerName) + "\t" +
                    EscapePortable(e.HandlerDeclaringType) + "\t" +
                    EscapePortable(e.IdentifiedCil));
            }
        }

        public static OpcodeMap ReadPortableMap(string path)
        {
            var map = new OpcodeMap();
            if (!File.Exists(path))
            {
                map.ErrorMessage = "portable map file not found";
                return map;
            }

            string[] lines;
            try { lines = File.ReadAllLines(path); }
            catch (Exception ex)
            {
                map.ErrorMessage = "portable map read failed: " + ex.Message;
                return map;
            }
            if (lines.Length == 0)
            {
                map.ErrorMessage = "portable map file is empty";
                return map;
            }

            var header = lines[0];
            if (header.StartsWith("ERROR\t", StringComparison.Ordinal))
            {
                map.ErrorMessage = UnescapePortable(header.Substring("ERROR\t".Length));
                return map;
            }
            if (!header.Equals("OK", StringComparison.Ordinal))
            {
                map.ErrorMessage = "portable map header invalid";
                return map;
            }

            for (int i = 1; i < lines.Length; i++)
            {
                if (string.IsNullOrWhiteSpace(lines[i])) continue;
                var parts = lines[i].Split(new[] { '\t' }, 5);
                if (parts.Length < 5) continue;
                if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var opcode))
                    continue;
                uint? tok = null;
                if (!string.IsNullOrWhiteSpace(parts[1]) &&
                    uint.TryParse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var tokVal))
                    tok = tokVal;

                map.Entries.Add(new OpcodeEntry
                {
                    OpcodeId = opcode,
                    HandlerToken = tok,
                    HandlerName = UnescapePortable(parts[2]),
                    HandlerDeclaringType = UnescapePortable(parts[3]),
                    IdentifiedCil = UnescapePortable(parts[4])
                });
            }

            return map;
        }

        private static string EscapePortable(string s) =>
            string.IsNullOrEmpty(s) ? "" : Uri.EscapeDataString(s);

        private static string UnescapePortable(string s) =>
            string.IsNullOrEmpty(s) ? "" : Uri.UnescapeDataString(s);

        /// <summary>
        /// Classifies each opcode entry by running eazdevirt's V1 detectors
        /// against the handler delegate method. Fills e.IdentifiedCil when
        /// a match is found. Returns counts.
        /// </summary>
        public static (int total, int identified) Classify(OpcodeMap map, ModuleDefMD module, EazModule eazModule)
        {
            int id = 0;
            foreach (var e in map.Entries)
            {
                if (!e.HandlerToken.HasValue) continue;
                var md = module.ResolveMethod(e.HandlerToken.Value & 0xFFFFFF) as MethodDef;
                if (md == null) continue;

                // The 2018 detectors expect the handler to be the outer "delegate method".
                // In 2025.x that's still true at the callvirt level.
                VirtualOpCode v;
                try
                {
                    v = VirtualOpCode.FromDynamic(eazModule, e.OpcodeId, md);
                }
                catch
                {
                    continue;
                }
                if (v.IsIdentified)
                {
                    try
                    {
                        e.IdentifiedCil = v.DetectAttribute?.IsSpecial == true
                            ? "SPECIAL:" + v.DetectAttribute.SpecialOpCode
                            : v.OpCode.ToString();
                        id++;
                    }
                    catch { }
                }
            }
            return (map.Entries.Count, id);
        }

        private static bool TryPrime(Assembly asm, out string message)
        {
            message = null;
            foreach (var t in SafeGetTypes(asm))
            {
                foreach (var mi in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {
                    MethodBody body;
                    try { body = mi.GetMethodBody(); } catch { continue; }
                    if (body == null) continue;
                    var il = body.GetILAsByteArray();
                    if (il == null) continue;
                    // ldstr opcode is 0x72 followed by 4-byte string token.
                    for (int i = 0; i < il.Length - 4; i++)
                    {
                        if (il[i] != 0x72) continue;
                        uint strTok = BitConverter.ToUInt32(il, i + 1);
                        string s;
                        try { s = mi.Module.ResolveString((int)strTok); }
                        catch { continue; }
                        if (s == null || s.Length != 10) continue;

                        // Found a primer candidate. Invoke with default args.
                        var ps = mi.GetParameters();
                        var argv = new object[ps.Length];
                        for (int j = 0; j < ps.Length; j++)
                            argv[j] = ps[j].ParameterType.IsValueType ? Activator.CreateInstance(ps[j].ParameterType) : null;
                        object inst = null;
                        if (!mi.IsStatic)
                        {
                            try { inst = Activator.CreateInstance(mi.DeclaringType); }
                            catch { continue; }
                        }
                        try
                        {
                            mi.Invoke(inst, argv);
                            message = "primed via " + mi.Name;
                            return true;
                        }
                        catch (Exception ex)
                        {
                            // Some stubs throw due app-level dependencies or runtime state.
                            // Keep searching for another primer candidate instead of stopping.
                            message = "primer threw: " + (ex.InnerException?.Message ?? ex.Message);
                            continue;
                        }
                    }
                }
            }
            message = "no primer found";
            return false;
        }

        private static IEnumerable<Type> SafeGetTypes(Assembly asm)
        {
            try { return asm.GetTypes(); }
            catch (ReflectionTypeLoadException e) { return e.Types.Where(x => x != null); }
            catch { return Array.Empty<Type>(); }
        }

        private static IEnumerable<FieldInfo> SafeGetStaticFields(Type t)
        {
            try { return t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static); }
            catch { return Array.Empty<FieldInfo>(); }
        }
    }
}

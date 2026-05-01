using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer.Processors
{
    internal class AssemblyResolver : ProcessorBase
    {
        private TypeDef _assemblyResolver;
        private MethodDef _moveNext;
        private List<EmbeddedAssemblyInfo> _assemblies;
        private MethodInfo _decrypter;
        private MethodInfo _decompressor;

        protected override void InitializeInternal()
        {
            //try to find the embedded assemblies string, which is located in 
            //the iterator in the EnumerateEmbeddedAssemblies function
            if (!Flags.AsmResTypeTok.IsNull)
                _assemblyResolver = Ctx.Module.ResolveToken(Flags.AsmResTypeTok) as TypeDef
                                    ?? throw new Exception("AssemblyResolver token set but type not found");
            else
                _assemblyResolver = Ctx.Module.Types.SingleOrDefault(CanBeAssemblyResolver)
                                    ?? throw new Exception("Could not find resolver type");

            if (!Flags.AsmResMoveNextTok.IsNull)
                _moveNext = Ctx.Module.ResolveToken(Flags.AsmResMoveNextTok) as MethodDef
                            ?? throw new Exception("MoveNext token set but type not found");
            else
            {
                var extractionApi = _assemblyResolver.NestedTypes.SingleOrDefault(CanBeExtractionApi)
                                    ?? throw new Exception("Could not find assembly extraction helper");
                var enumerable = extractionApi.NestedTypes.SingleOrDefault(CanBeEnumerable)
                                 ?? throw new Exception("Could not find EnumerateEmbeddedAssemblies iterator");
                _moveNext = enumerable.Methods.SingleOrDefault(CanBeMoveNext)
                            ?? throw new Exception("Could not find EnumerateEmbeddedAssemblies's MoveNext");  
            }

            //find the decryption methods

            MethodDef dec1;
            if (!Flags.AsmResDecryptTok.IsNull)
                dec1 = Ctx.Module.ResolveToken(Flags.AsmResDecryptTok) as MethodDef
                       ?? throw new Exception("Decrypter token set but method not found");
            else
                dec1 = _assemblyResolver.Methods.SingleOrDefault(CanBeDecryptionMethod)
                       ?? throw new Exception("Could not find decryption method");

            _decrypter = Utils.FindMethod(Ctx.Assembly, dec1, new[] { typeof(byte[]) })
                         ?? throw new Exception("Couldn't find decrypter through reflection");

            MethodDef dec2;
            if (!Flags.AsmResDecompressTok.IsNull)
                dec2 = Ctx.Module.ResolveToken(Flags.AsmResDecompressTok) as MethodDef
                        ?? throw new Exception("Decompressor token set but method not found");
            else
                dec2 = _assemblyResolver.Methods.SingleOrDefault(CanBeDecompressionMethod);

            //this one may be null
            if (dec2 != null)
                _decompressor = Utils.FindMethod(Ctx.Assembly, dec2, new[] {typeof(byte[])})
                                ?? throw new Exception("Couldn't find prefix remover through reflection");
        }

        protected override void ProcessInternal()
        {
            //get path to write to
            var path = Path.GetDirectoryName(Ctx.InputFile);

            //get assemblies
            //this happens here because we need string to be decrypted
            if (!Ctx.Get<StringFixer>().Processed) throw new Exception("StringFixer is required!");
            var str = _moveNext.Body.Instructions.SingleOrDefault(a => a.OpCode.Code == Code.Ldstr)?.Operand as string
                      ?? throw new Exception("Could not find assembly list");
            
            // AssemblyNames that start with `#A,A,` seem to be copies but with a version attached
            _assemblies = EnumerateEmbeddedAssemblies(str).Where(a => !a.Fullname.StartsWith("#A,A,")).ToList();

            //get the resource resolver and figure out which assemblies we shouldn't extract
            var res = Ctx.Get<ResourceResolver>();
            IEnumerable<EmbeddedAssemblyInfo> asmEnumerator = res.Initialized
                ? _assemblies.Where(a => res.ResourceAssemblies.All(b => !string.Equals(b.GetName().Name, new AssemblyName(a.Fullname).Name, StringComparison.CurrentCultureIgnoreCase)))
                : _assemblies;

            foreach (var assembly in asmEnumerator)
            {
                //get the resource containing the assembly
                string resName = assembly.ResourceName;
                var stream = Ctx.Assembly.GetManifestResourceStream(resName);    //not sure if reflection is the best way

                var read = 0;
                byte[] buffer = new byte[stream.Length];
                while (read < buffer.Length)
                    read += stream.Read(buffer, read, (int)stream.Length);

                //if the assembly is encrypted: decrypt it
                if (assembly.Encrypted) {
                    _decrypter.Invoke(null, new object[] {buffer});
                }
                //if the assembly is prefixed: remove it
                if (assembly.Compressed) {
                    if (_decompressor == null) throw new Exception("Assembly is compressed, but couldn't find decompressor method");
                    var resp = _decompressor.Invoke(null, new object[] {buffer});
                    if (resp is byte[] b)
                        buffer = b;
                }

                File.WriteAllBytes(Path.Combine(path, assembly.Filename), buffer);
            }
        }

        protected override void CleanupInternal()
        {
            //remove the call to the method that sets OnAssemblyResolve
            var modType = Ctx.Module.GlobalType ?? throw new Exception("Could not find <Module>");
            var instructions = modType.FindStaticConstructor()?.Body?.Instructions ?? throw new Exception("Missing <Module> .cctor");
            foreach (Instruction instr in instructions)
            {
                if (instr.OpCode.Code != Code.Call) continue;
                if (!(instr.Operand is MethodDef md)) continue;

                if (md.DeclaringType == _assemblyResolver)
                    instr.OpCode = OpCodes.Nop;
            }

            //remove types
            if (_decompressor == null) //if it is present, more stuff is going on that I don't know about (better be safe)
                Utils.RemoveTypeIfUnreferenced(Ctx.Module, _assemblyResolver);

            //remove resources
            foreach (var assembly in _assemblies)
                Ctx.Module.Resources.Remove(Ctx.Module.Resources.SingleOrDefault(a => a.Name == assembly.ResourceName)
                                            ?? throw new Exception("Resource name not unique (or present)"));
        }

        private bool CanBeAssemblyResolver(TypeDef t)
        {
            if (t.Methods.Count(a => a.IsPinvokeImpl) != 1) return false;   //MoveFileEx
            if (t.NestedTypes.Count < 4) return false; //AssemblyCache, AssemblyRepresentation, ExtractionApi, RNG

            foreach (MethodDef m in t.Methods.Where(a => a.HasBody && a.Body.HasInstructions)) {
                //adds AssemblyResolver
                bool addsResolver = m.Body.Instructions.Any(i => i.OpCode.Code == Code.Callvirt && i.Operand is MemberRef mr && mr.Name == "add_AssemblyResolve");
                if (addsResolver)
                    return true;
            }

            return false;
        }

        private bool CanBeExtractionApi(TypeDef t) => t.HasNestedTypes && t.IsAbstract && t.IsSealed && t.NestedTypes.Any(CanBeEnumerable);
        private bool CanBeEnumerable(TypeDef t) => t.HasInterfaces && t.Interfaces.Any(a => a.Interface.Name == "IEnumerable");
        private bool CanBeMoveNext(MethodDef m) => m.Overrides.Any(a => a.MethodDeclaration.FullName == "System.Boolean System.Collections.IEnumerator::MoveNext()");

        private bool CanBeDecryptionMethod(MethodDef m) => m.MethodSig.ToString() == "System.Byte[] (System.Byte[])" && m.IsNoInlining;
        private bool CanBeDecompressionMethod(MethodDef m) => m.MethodSig.ToString() == "System.Byte[] (System.Byte[])" && !m.IsNoInlining;

        private static IEnumerable<EmbeddedAssemblyInfo> EnumerateEmbeddedAssemblies(string text)
        {
            var split = text.Split(',');

            // newer versions of eaz have an extra entry at the start, so skip that
            var firstIndex = split.Length % 4;
            for (int i = firstIndex; i < split.Length; i += 4)
            {
                string b64 = split[i];
                string resName = split[i + 1];
                var asm = new EmbeddedAssemblyInfo { FullnameBase64 = b64 };

                //check flags
                int posPipe = resName.IndexOf('|');
                if (posPipe >= 0)
                {
                    string flags = resName.Substring(0, posPipe);
                    resName = resName.Substring(posPipe + 1);

                    asm.Encrypted = flags.IndexOf('a') != -1;
                    asm.Compressed = flags.IndexOf('b') != -1;
                    asm.MustLoadfromDisk = flags.IndexOf('c') != -1;
                    asm.AlternateDirectory = flags.IndexOf('f') != -1;
                }
                asm.ResourceName = resName;
                asm.FilenameBase64 = split[i + 2];

                yield return asm;
            }
        }

        [DebuggerDisplay("{" + nameof(Fullname) + "}")]
        internal class EmbeddedAssemblyInfo
        {
            public string Fullname {
                get {
                    if (_fullname != null) return _fullname;
                    byte[] array = Convert.FromBase64String(FullnameBase64);
                    return _fullname = Encoding.UTF8.GetString(array, 0, array.Length);
                }
            }

            public string Filename {
                get {
                    if (_filename != null) return _filename;
                    byte[] array = Convert.FromBase64String(FilenameBase64);
                    return _filename = Encoding.UTF8.GetString(array, 0, array.Length);
                }
            }

            public string FullnameBase64;
            public string ResourceName;
            public bool Encrypted;
            public bool Compressed;
            public bool MustLoadfromDisk;
            public bool AlternateDirectory;
            public string FilenameBase64;
            private string _fullname;
            private string _filename;
        }
    }
}

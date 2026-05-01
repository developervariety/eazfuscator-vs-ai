using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace eazdevirt
{
    internal sealed class ModernStaticBytecodeExtractor
    {
        private readonly EazModule _module;
        private readonly MethodStub[] _stubs;

        public ModernStaticBytecodeExtractor(EazModule module, MethodStub[] stubs)
        {
            _module = module;
            _stubs = stubs ?? Array.Empty<MethodStub>();
        }

        public Dictionary<uint, byte[]> Extract()
        {
            var result = new Dictionary<uint, byte[]>();
            if (_stubs.Length == 0)
                return result;

            var location = _module.Module.Location;
            if (String.IsNullOrWhiteSpace(location) || !File.Exists(location))
                return result;

            string tempPath = Path.Combine(
                Path.GetTempPath(),
                "eazfix-static-vm-" + Guid.NewGuid().ToString("N") + Path.GetExtension(location));

            try
            {
                WriteSanitizedAssembly(location, tempPath);
                var asm = Assembly.LoadFile(tempPath);

                foreach (var stub in _stubs)
                {
                    try
                    {
                        var bytes = ExtractOne(asm, stub);
                        if (bytes != null && bytes.Length > 0)
                            result[stub.Method.MDToken.Raw] = bytes;
                    }
                    catch
                    {
                        // Best-effort per method: one odd stub should not block
                        // static recovery for the rest of the module.
                    }
                }
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }

            return result;
        }

        private static void WriteSanitizedAssembly(string inputPath, string outputPath)
        {
            var tempModule = ModuleDefMD.Load(inputPath);
            var cctor = tempModule.GlobalType?.FindStaticConstructor();
            if (cctor != null)
            {
                cctor.Body.Instructions.Clear();
                cctor.Body.ExceptionHandlers.Clear();
                cctor.Body.Variables.Clear();
                cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            tempModule.Write(outputPath, new ModuleWriterOptions(tempModule)
            {
                MetadataOptions = new MetadataOptions(MetadataFlags.PreserveAll)
            });
        }

        private static byte[] ExtractOne(Assembly asm, MethodStub stub)
        {
            if (stub.VirtualCallMethod == null || stub.CreateStreamMethod == null)
                return null;

            var vmType = asm.ManifestModule.ResolveType(unchecked((int)stub.VirtualCallMethod.DeclaringType.MDToken.Raw));
            var vm = FormatterServices.GetUninitializedObject(vmType);

            var createStream = asm.ManifestModule.ResolveMethod(unchecked((int)stub.CreateStreamMethod.MDToken.Raw));
            var baseStream = (Stream)createStream.Invoke(null, new object[0]);

            var init = asm.ManifestModule.ResolveMethod(FindSetStreamMethod(stub.VirtualCallMethod.DeclaringType));
            init.Invoke(vm, new object[] { baseStream, stub.Position, null });

            foreach (var field in vmType.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            {
                if (field.FieldType != typeof(byte[]))
                    continue;
                var bytes = (byte[])field.GetValue(vm);
                if (bytes != null && bytes.Length > 0)
                    return bytes;
            }

            return null;
        }

        private static int FindSetStreamMethod(TypeDef vmType)
        {
            foreach (var method in vmType.Methods)
            {
                if (!method.HasBody || method.MethodSig == null)
                    continue;
                if (!method.ReturnType.FullName.Equals("System.Void"))
                    continue;
                var p = method.Parameters;
                if (p.Count == 4
                    && p[1].Type.FullName.Equals("System.IO.Stream")
                    && p[2].Type.FullName.Equals("System.Int64")
                    && p[3].Type.FullName.Equals("System.String"))
                    return unchecked((int)method.MDToken.Raw);
            }

            throw new MissingMethodException("Unable to find VM stream initializer");
        }
    }
}

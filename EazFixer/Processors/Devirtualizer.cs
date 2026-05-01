using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer.Processors
{
    internal class Devirtualizer : ProcessorBase
    {
        private global::eazdevirt.DevirtualizeResult _result;

        protected override void InitializeInternal()
        {
            if (Flags.NoDevirt)
                throw new Exception("skipped (--no-devirt)");
        }

        protected override void ProcessInternal()
        {
            var module = (ModuleDefMD)Ctx.Module;
            _result = global::eazdevirt.PublicApi.Devirtualize(module);

            int stubs = _result.DetectedStubs.Count;

            if (stubs == 0)
            {
                // Not virtualized at all — nothing to do, Process succeeds.
                Console.WriteLine("  Devirt: no virtualized methods detected (not using Eazfuscator VM)");
                return;
            }

            Console.WriteLine(
                "  Devirt: stubs={0}, devirted={1}/{2}, failed={3}, unknown-opcodes={4}",
                stubs,
                _result.MethodsDevirted,
                _result.MethodsDetected,
                _result.FailedMethods.Count,
                _result.UnrecognizedOpcodes.Count);

            foreach (var s in _result.DetectedStubs)
            {
                Console.WriteLine("    stub: 0x{0:X8}  ->  {1}", s.Token, s.FullName);
                if (!string.IsNullOrEmpty(s.PositionString))
                    Console.WriteLine("      position: \"{0}\"  resource: {1}", s.PositionString, s.ResourceStringId ?? "(unknown)");
                if (s.VmTypeToken.HasValue)
                    Console.WriteLine("      vm-type:  0x{0:X8}  dispatcher: 0x{1:X8}", s.VmTypeToken.Value, s.DispatcherToken.GetValueOrDefault());
            }
            foreach (var m in _result.FailedMethods)
                Console.WriteLine("    fail: " + m);
            foreach (var o in _result.UnrecognizedOpcodes)
                Console.WriteLine("    unknown-opcode: 0x" + o);

            if (_result.ErrorMessage != null)
            {
                // Partial result: we have stub info but the pipeline couldn't
                // run (e.g. modern Eazfuscator crypto unrecognized). Surface
                // the underlying error but don't fail the whole processor —
                // the stub list is real, actionable output.
                Console.WriteLine("  Devirt: pipeline error (detect-only result is still valid): " + _result.ErrorMessage);
            }

            if (_result.MethodsDevirted < stubs && !Flags.KeepTypes)
            {
                Flags.KeepTypes = true;
                Console.WriteLine("  Devirt: keeping obfuscator types because VM stubs remain in the module");
            }

            // Dump encrypted VM resources to sidecar files so users have raw
            // bytes to feed into offline analysis.
            if (_result.VmResources.Count > 0 && !string.IsNullOrEmpty(Flags.OutFile))
            {
                var dir = Path.GetDirectoryName(Flags.OutFile);
                var baseName = Path.GetFileNameWithoutExtension(Flags.OutFile);
                foreach (var kvp in _result.VmResources)
                {
                    var safeName = kvp.Key;
                    foreach (var c in Path.GetInvalidFileNameChars())
                        safeName = safeName.Replace(c, '_');
                    var outPath = Path.Combine(dir ?? string.Empty, baseName + ".vmres." + safeName + ".bin");
                    try
                    {
                        File.WriteAllBytes(outPath, kvp.Value);
                        Console.WriteLine("    dumped VM resource ({0} bytes) -> {1}", kvp.Value.Length, outPath);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("    failed to dump VM resource {0}: {1}", kvp.Key, ex.Message);
                    }
                }
            }
        }

        protected override void CleanupInternal()
        {
            if (Flags.KeepVmTypes || _result == null)
                return;
            if (_result.MethodsDetected == 0 || _result.MethodsDevirted < _result.MethodsDetected)
                return;

            var module = (ModuleDefMD)Ctx.Module;

            foreach (var vmToken in _result.DetectedStubs
                         .Where(s => s.VmTypeToken.HasValue)
                         .Select(s => s.VmTypeToken.Value)
                         .Distinct()
                         .ToArray())
            {
                if (!(module.ResolveToken(vmToken) is TypeDef vmType))
                    continue;

                RemoveDeadVmFactoryMethods(module, vmType);
                RewriteAssemblyAnchorLdtoken(module, vmType);
                if (Utils.RemoveTypeIfUnreferenced(module, vmType) && Flags.PreserveAll)
                {
                    Flags.PreserveAll = false;
                    Console.WriteLine("  Devirt: disabled metadata token preservation after removing VM support types");
                }
            }

            foreach (var resourceName in _result.VmResources.Keys.ToArray())
            {
                var resource = module.Resources.FindEmbeddedResource(resourceName);
                if (resource != null)
                    module.Resources.Remove(resource);
            }
        }

        private static void RemoveDeadVmFactoryMethods(ModuleDefMD module, TypeDef vmType)
        {
            var changed = true;
            while (changed)
            {
                changed = false;
                foreach (var type in module.GetTypes().ToArray())
                {
                    if (type == vmType || IsNestedIn(type, vmType))
                        continue;

                    foreach (var method in type.Methods.ToArray())
                    {
                        if (!Utils.MethodSignatureReferencesType(method, vmType))
                            continue;
                        if (Utils.LookForMethodReferences(module, method))
                            continue;

                        type.Methods.Remove(method);
                        changed = true;
                    }
                }
            }
        }

        private static void RewriteAssemblyAnchorLdtoken(ModuleDefMD module, TypeDef vmType)
        {
            foreach (var type in module.GetTypes().ToArray())
            {
                if (type == vmType || IsNestedIn(type, vmType))
                    continue;

                foreach (var method in type.Methods.Where(m => m.HasBody && m.Body.HasInstructions))
                {
                    foreach (var instr in method.Body.Instructions)
                    {
                        if (instr.OpCode.Code != Code.Ldtoken)
                            continue;
                        if (!(instr.Operand is TypeDef td) || td != vmType)
                            continue;

                        instr.Operand = method.DeclaringType;
                    }
                }
            }
        }

        private static bool IsNestedIn(TypeDef type, TypeDef parent)
        {
            for (var cur = type?.DeclaringType; cur != null; cur = cur.DeclaringType)
            {
                if (cur == parent)
                    return true;
            }
            return false;
        }
    }
}

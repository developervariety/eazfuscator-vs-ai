using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using EazFixer.Processors;

namespace EazFixer
{
    internal class EazContext : IEnumerable<ProcessorBase>
    {
        public ModuleDef Module;
        public Assembly Assembly;
        public string InputFile;
        public string ReflectionFile;
        public ProcessorBase[] Processors;

        public EazContext(string file, ProcessorBase[] procs)
        {
            file = Path.GetFullPath(file);
            if (!File.Exists(file)) throw new Exception($"Failed (File: {file} does not exist)");

            InputFile = file;
            Module = ModuleDefMD.Load(file);
            ReflectionFile = CreateReflectionSafeCopy(file);
            Assembly = Assembly.LoadFile(ReflectionFile);
            Processors = procs;
        }

        private static string CreateReflectionSafeCopy(string file)
        {
            var outPath = Path.Combine(
                Path.GetTempPath(),
                "eazfix-reflect-" + Guid.NewGuid().ToString("N") + Path.GetExtension(file));

            var module = ModuleDefMD.Load(file);
            var cctor = module.GlobalType?.FindStaticConstructor();
            if (cctor != null)
            {
                cctor.Body.Instructions.Clear();
                cctor.Body.ExceptionHandlers.Clear();
                cctor.Body.Variables.Clear();
                cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }

            module.Write(outPath, new ModuleWriterOptions(module)
            {
                MetadataOptions = new MetadataOptions(MetadataFlags.PreserveAll)
            });
            return outPath;
        }

        //allow enumerating Processors
        public IEnumerator<ProcessorBase> GetEnumerator() => Processors.AsEnumerable().GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        //allow easily getting other processors by type
        public T Get<T>() where T : ProcessorBase => (T)this[typeof(T)];
        public ProcessorBase this[Type index] => Processors.Single(a => a.GetType() == index);
    }
}

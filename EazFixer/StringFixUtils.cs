using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer
{
    public static class StringFixUtils
    {
        public static MethodDef FindStringDecryptMethod(ModuleDef module)
        {
            // Eazfuscator may have multiple string decryptor methods (e.g. separate
            // decryptors for different subsystems). Pick the first match rather than
            // throwing on duplicates. If the first doesn't work, downstream callers
            // can use --str-decrypt-tok to specify the correct one.
            return Utils.GetMethodsRecursive(module).FirstOrDefault(CanBeStringMethod);
        }

        private static bool CanBeStringMethod(MethodDef method)
        {
            //internal and static
            if (!method.IsStatic || !method.IsAssembly)
                return false;

            //takes int, returns string
            if (method.MethodSig.ToString() != "System.String (System.Int32)")
                return false;

            //actually a proper method, not abstract or from an interface
            if (!method.HasBody || !method.Body.HasInstructions)
                return false;

            //calls the second resolve method (used if string isn't in cache)
            if (!method.Body.Instructions.Any(a => a.OpCode.Code == Code.Call && a.Operand is MethodDef m
                                                                              && m.MethodSig.ToString() == "System.String (System.Int32,System.Boolean)"))
                return false;
                
            //is not private or public
            if (method.IsPrivate || method.IsPublic)
                return false;


            return true;
        }
    }
}
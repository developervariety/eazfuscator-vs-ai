using System;
using System.Collections.Generic;
using System.Globalization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer
{
    /// <summary>
    /// Rewrites a method body to immediately return a constant value.
    /// Useful for neutering feature gates / activation stubs
    /// in a binary you own.
    ///
    /// Value-spec grammar:
    ///   true             -> bool true
    ///   false            -> bool false
    ///   void             -> plain ret (method must return void)
    ///   null             -> ldnull; ret (method must return a reference type)
    ///   int:&lt;n&gt;          -> ldc.i4 n; ret   (also valid for bool via 0/1)
    ///   long:&lt;n&gt;         -> ldc.i8 n; ret
    ///   string:&lt;text&gt;    -> ldstr "text"; ret
    /// </summary>
    internal static class ReturnPatcher
    {
        // spec "bool-args-false": in-place surgery — replaces every ldarg that is immediately
        // followed by "box System.Boolean" with ldc.i4.0, forcing all boxed-bool arguments false.
        // Used for eval-state notifier and context-builder methods that pack bools into an object[].
        private static void ApplyBoolArgsToFalse(MethodDef method)
        {
            if (!method.HasBody)
                throw new Exception("method has no body");

            var instrs = method.Body.Instructions;
            int changes = 0;
            for (int i = 0; i < instrs.Count - 1; i++)
            {
                var instr = instrs[i];
                var next  = instrs[i + 1];

                bool isArgLoad =
                    instr.OpCode == OpCodes.Ldarg_0 || instr.OpCode == OpCodes.Ldarg_1 ||
                    instr.OpCode == OpCodes.Ldarg_2 || instr.OpCode == OpCodes.Ldarg_3 ||
                    instr.OpCode == OpCodes.Ldarg_S  || instr.OpCode == OpCodes.Ldarg;

                bool isBoxedBool = next.OpCode == OpCodes.Box &&
                    (next.Operand as ITypeDefOrRef)?.FullName == "System.Boolean";

                if (isArgLoad && isBoxedBool)
                {
                    instr.OpCode  = OpCodes.Ldc_I4_0;
                    instr.Operand = null;
                    changes++;
                }
            }

            if (changes == 0)
                throw new Exception("no ldarg+box(System.Boolean) pairs found");
        }

        public static void ApplyAll(ModuleDefMD module, IEnumerable<(uint Token, string ValueSpec)> specs)
        {
            foreach (var (token, spec) in specs)
            {
                try
                {
                    Apply(module, token, spec);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("  patch 0x{0:X8}={1} FAILED: {2}", token, spec, ex.Message);
                }
            }
        }

        public static void Apply(ModuleDefMD module, uint token, string spec)
        {
            if (module.ResolveToken(token) is not MethodDef method)
                throw new Exception($"token 0x{token:X8} does not resolve to a method");

            if (spec.Equals("bool-args-false", StringComparison.OrdinalIgnoreCase))
            {
                ApplyBoolArgsToFalse(method);
                Console.WriteLine("  patched 0x{0:X8} -> bool-args-false  ({1})", token, SafeName(method));
                return;
            }

            var retType = method.ReturnType?.FullName ?? "System.Void";
            var body = new CilBody
            {
                InitLocals = false,
                MaxStack = 2
            };

            switch (spec.ToLowerInvariant())
            {
                case "true":
                    Require(retType, "System.Boolean", "--patch ...=true");
                    body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                    body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    break;
                case "false":
                    Require(retType, "System.Boolean", "--patch ...=false");
                    body.Instructions.Add(OpCodes.Ldc_I4_0.ToInstruction());
                    body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    break;
                case "void":
                    Require(retType, "System.Void", "--patch ...=void");
                    body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    break;
                case "null":
                    if (retType == "System.Void")
                        throw new Exception("--patch ...=null on void method; use =void");
                    if (method.ReturnType.IsValueType)
                        throw new Exception($"--patch ...=null on value-type return ({retType}); use =int:0 or =long:0");
                    body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                    body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    break;
                default:
                    ApplyTyped(body, retType, spec);
                    break;
            }

            method.FreeMethodBody();
            method.Body = body;
            // Strip any remaining local variables (body above declares none)
            // and exception handlers — not needed for a return-constant stub.

            Console.WriteLine("  patched 0x{0:X8} -> {1,-20}  ({2})", token, spec, SafeName(method));
        }

        private static void ApplyTyped(CilBody body, string retType, string spec)
        {
            var colon = spec.IndexOf(':');
            if (colon < 0)
                throw new Exception($"unknown spec '{spec}' (expected one of: true, false, void, null, int:N, long:N, string:text)");
            var kind = spec.Substring(0, colon).ToLowerInvariant();
            var val = spec.Substring(colon + 1);

            switch (kind)
            {
                case "int":
                    {
                        int n = int.Parse(val, NumberStyles.Integer, CultureInfo.InvariantCulture);
                        // Accept int for bool return too (0/1).
                        if (retType != "System.Int32" && retType != "System.UInt32"
                            && retType != "System.Int16" && retType != "System.UInt16"
                            && retType != "System.Byte"  && retType != "System.SByte"
                            && retType != "System.Boolean")
                            throw new Exception($"int spec doesn't match return type {retType}");
                        body.Instructions.Add(Instruction.CreateLdcI4(n));
                        body.Instructions.Add(OpCodes.Ret.ToInstruction());
                        break;
                    }
                case "long":
                    {
                        long n = long.Parse(val, NumberStyles.Integer, CultureInfo.InvariantCulture);
                        if (retType != "System.Int64" && retType != "System.UInt64")
                            throw new Exception($"long spec doesn't match return type {retType}");
                        body.Instructions.Add(OpCodes.Ldc_I8.ToInstruction(n));
                        body.Instructions.Add(OpCodes.Ret.ToInstruction());
                        break;
                    }
                case "string":
                    {
                        if (retType != "System.String")
                            throw new Exception($"string spec doesn't match return type {retType}");
                        body.Instructions.Add(OpCodes.Ldstr.ToInstruction(val));
                        body.Instructions.Add(OpCodes.Ret.ToInstruction());
                        break;
                    }
                default:
                    throw new Exception($"unknown spec kind '{kind}'");
            }
        }

        private static void Require(string actual, string expected, string help)
        {
            if (!string.Equals(actual, expected, StringComparison.Ordinal))
                throw new Exception($"{help} but method returns {actual}, not {expected}");
        }

        private static string SafeName(MethodDef m)
        {
            try { return m.FullName; }
            catch { return "<unprintable>"; }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer
{
    public static class Utils
    {
        public static IEnumerable<MethodDef> GetMethodsRecursive(ModuleDef t) => t.Types.SelectMany(GetMethodsRecursive);
        public static IEnumerable<MethodDef> GetMethodsRecursive(TypeDef type)
        {
            //return all methods in this type
            foreach (MethodDef m in type.Methods)
                yield return m;

            //go through nested types
            foreach (TypeDef t in type.NestedTypes)
            foreach (MethodDef m in GetMethodsRecursive(t))
                yield return m;
        }

        public static MethodInfo FindMethod(Assembly ass, MethodDef meth, Type[] args)
        {
            var flags = BindingFlags.Default;
            flags |= meth.IsPublic ? BindingFlags.Public : BindingFlags.NonPublic;
            flags |= meth.IsStatic ? BindingFlags.Static : BindingFlags.Instance;

            //BUG: this can fail
            Type type = ass.GetType(meth.DeclaringType.ReflectionFullName);
            return type?.GetMethod(meth.Name, flags, null, args, null);
        }

        public static bool LookForReferences(ModuleDef mod, MethodDef meth) //methoddef can be generalized
        {
            //Why LINQ you may ask? Because I can :)
            return GetMethodsRecursive(mod)
                .Where(m => m.HasBody && m.Body.HasInstructions)
                .SelectMany(m => m.Body.Instructions)
                .Any(i => i.Operand != null && i.Operand == meth);
        }

        public static bool LookForReferences(ModuleDef mod, TypeDef type)
        {
            if (mod == null || type == null) return false;
            var blocked = new HashSet<TypeDef>(GetSelfAndNested(type));

            foreach (var t in mod.GetTypes())
            {
                if (blocked.Contains(t)) continue;

                if (ReferencesType(t.BaseType, blocked)) return true;
                if (t.Interfaces.Any(i => ReferencesType(i.Interface, blocked))) return true;
                if (t.GenericParameters.Any(gp => gp.GenericParamConstraints.Any(c => ReferencesType(c.Constraint, blocked)))) return true;
                if (t.CustomAttributes.Any(ca => ReferencesType(ca.AttributeType, blocked))) return true;
                if (t.Fields.Any(f => ReferencesType(f.FieldType, blocked))) return true;
                if (t.Fields.Any(f => f.CustomAttributes.Any(ca => ReferencesType(ca.AttributeType, blocked)))) return true;
                if (t.Methods.Any(m => ReferencesType(m.MethodSig, blocked))) return true;

                foreach (var method in t.Methods.Where(m => m.HasBody && m.Body.HasInstructions))
                {
                    if (method.GenericParameters.Any(gp => gp.GenericParamConstraints.Any(c => ReferencesType(c.Constraint, blocked)))) return true;
                    if (method.CustomAttributes.Any(ca => ReferencesType(ca.AttributeType, blocked))) return true;
                    if (method.Body.Variables.Any(v => ReferencesType(v.Type, blocked))) return true;
                    if (method.Body.ExceptionHandlers.Any(eh => ReferencesType(eh.CatchType, blocked))) return true;

                    foreach (var instr in method.Body.Instructions)
                    {
                        if (ReferencesType(instr.Operand, blocked))
                            return true;
                    }
                }
            }

            return false;
        }

        public static bool RemoveTypeIfUnreferenced(ModuleDef mod, TypeDef type)
        {
            if (mod == null || type == null) return false;
            if (LookForReferences(mod, type)) return false;
            if (type.DeclaringType != null)
                return type.DeclaringType.NestedTypes.Remove(type);
            return mod.Types.Remove(type);
        }

        public static bool LookForMethodReferences(ModuleDef mod, MethodDef method)
        {
            if (mod == null || method == null) return false;
            foreach (var m in GetMethodsRecursive(mod).Where(m => m.HasBody && m.Body.HasInstructions))
            {
                if (m == method) continue;
                foreach (var instr in m.Body.Instructions)
                {
                    if (instr.Operand == method)
                        return true;
                    if (instr.Operand is IMethod im && im.ResolveMethodDef() == method)
                        return true;
                }
            }
            return false;
        }

        public static bool MethodSignatureReferencesType(MethodDef method, TypeDef type)
        {
            if (method?.MethodSig == null || type == null) return false;
            return ReferencesType(method.MethodSig, new HashSet<TypeDef>(GetSelfAndNested(type)));
        }

        private static IEnumerable<TypeDef> GetSelfAndNested(TypeDef type)
        {
            yield return type;
            foreach (var nested in type.NestedTypes)
            foreach (var t in GetSelfAndNested(nested))
                yield return t;
        }

        private static bool ReferencesType(object obj, ISet<TypeDef> types)
        {
            switch (obj)
            {
                case null:
                    return false;
                case TypeDef td:
                    return types.Contains(td);
                case ITypeDefOrRef tr:
                    return types.Contains(tr.ResolveTypeDef());
                case TypeSig sig:
                    return ReferencesTypeSig(sig, types);
                case MethodSig ms:
                    return ReferencesType(ms.RetType, types) || ms.Params.Any(p => ReferencesType(p, types));
                case FieldSig fs:
                    return ReferencesType(fs.Type, types);
                case MemberRef mr:
                    return ReferencesType(mr.DeclaringType, types) || ReferencesType(mr.MethodSig, types) || ReferencesType(mr.FieldSig, types);
                case MethodSpec spec:
                    return ReferencesType(spec.Method, types) || spec.GenericInstMethodSig.GenericArguments.Any(a => ReferencesType(a, types));
                case MethodDef md:
                    return ReferencesType(md.DeclaringType, types) || ReferencesType(md.MethodSig, types);
                case IMethod im:
                    return ReferencesType(im.DeclaringType, types) || ReferencesType(im.MethodSig, types);
                case FieldDef fd:
                    return ReferencesType(fd.DeclaringType, types) || ReferencesType(fd.FieldType, types);
                case IField iff:
                    return ReferencesType(iff.DeclaringType, types) || ReferencesType(iff.FieldSig, types);
                case ITokenOperand tok:
                    return ReferencesType(tok, types);
                default:
                    return false;
            }
        }

        private static bool ReferencesTypeSig(TypeSig sig, ISet<TypeDef> types)
        {
            while (sig != null)
            {
                if (sig is TypeDefOrRefSig tdr && ReferencesType(tdr.TypeDefOrRef, types))
                    return true;
                if (sig is GenericInstSig gis)
                    return ReferencesTypeSig(gis.GenericType, types) || gis.GenericArguments.Any(a => ReferencesTypeSig(a, types));
                sig = sig.Next;
            }
            return false;
        }
    }
}

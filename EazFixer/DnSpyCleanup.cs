using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using dnlib.DotNet;

namespace EazFixer
{
    internal static class DnSpyCleanup
    {
        public sealed class Result
        {
            public int TypesRenamed;
            public int MethodsRenamed;
            public int FieldsRenamed;
            public int PropertiesRenamed;
            public int EventsRenamed;
            public int GenericParametersRenamed;

            public int Total =>
                TypesRenamed + MethodsRenamed + FieldsRenamed +
                PropertiesRenamed + EventsRenamed + GenericParametersRenamed;
        }

        public static Result Run(ModuleDef module)
        {
            var result = new Result();
            var typeIndex = 0;

            foreach (var type in module.GetTypes().Where(t => t != module.GlobalType).ToArray())
            {
                if (NeedsCleanup(type.Namespace))
                    type.Namespace = "Cleaned";

                if (NeedsCleanup(type.Name))
                {
                    type.Name = type.DeclaringType == null
                        ? "Type_" + (++typeIndex).ToString("D5", CultureInfo.InvariantCulture)
                        : "Nested_" + (++typeIndex).ToString("D5", CultureInfo.InvariantCulture);
                    result.TypesRenamed++;
                }

                result.GenericParametersRenamed += RenameGenericParameters(type.GenericParameters);
                result.MethodsRenamed += RenameMethods(type);
                result.FieldsRenamed += RenameFields(type);
                result.PropertiesRenamed += RenameProperties(type);
                result.EventsRenamed += RenameEvents(type);
            }

            return result;
        }

        private static int RenameMethods(TypeDef type)
        {
            var renamed = 0;
            var index = 0;
            foreach (var method in type.Methods)
            {
                renamed += RenameGenericParameters(method.GenericParameters);
                if (method.IsConstructor || method.IsRuntimeSpecialName)
                    continue;
                if (!NeedsCleanup(method.Name))
                    continue;

                method.Name = "method_" + (++index).ToString("D5", CultureInfo.InvariantCulture);
                renamed++;
            }
            return renamed;
        }

        private static int RenameFields(TypeDef type)
        {
            var renamed = 0;
            var index = 0;
            foreach (var field in type.Fields)
            {
                if (field.IsRuntimeSpecialName || !NeedsCleanup(field.Name))
                    continue;

                field.Name = "field_" + (++index).ToString("D5", CultureInfo.InvariantCulture);
                renamed++;
            }
            return renamed;
        }

        private static int RenameProperties(TypeDef type)
        {
            var renamed = 0;
            var index = 0;
            foreach (var property in type.Properties)
            {
                if (!NeedsCleanup(property.Name))
                    continue;

                property.Name = "Property_" + (++index).ToString("D5", CultureInfo.InvariantCulture);
                renamed++;
            }
            return renamed;
        }

        private static int RenameEvents(TypeDef type)
        {
            var renamed = 0;
            var index = 0;
            foreach (var evt in type.Events)
            {
                if (!NeedsCleanup(evt.Name))
                    continue;

                evt.Name = "Event_" + (++index).ToString("D5", CultureInfo.InvariantCulture);
                renamed++;
            }
            return renamed;
        }

        private static int RenameGenericParameters(IList<GenericParam> parameters)
        {
            var renamed = 0;
            for (var i = 0; i < parameters.Count; i++)
            {
                if (!NeedsCleanup(parameters[i].Name))
                    continue;

                parameters[i].Name = "T" + i.ToString(CultureInfo.InvariantCulture);
                renamed++;
            }
            return renamed;
        }

        private static bool NeedsCleanup(UTF8String name)
        {
            return NeedsCleanup(name.String);
        }

        private static bool NeedsCleanup(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return true;
            if (name == ".ctor" || name == ".cctor" || name == "value__")
                return false;

            var hasAsciiLetterOrDigit = false;
            foreach (var ch in name)
            {
                if (ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9')
                {
                    hasAsciiLetterOrDigit = true;
                    continue;
                }
                if (ch == '_' || ch == '<' || ch == '>' || ch == '$')
                    continue;

                var cat = CharUnicodeInfo.GetUnicodeCategory(ch);
                if (cat == UnicodeCategory.Control ||
                    cat == UnicodeCategory.Format ||
                    cat == UnicodeCategory.OtherNotAssigned ||
                    cat == UnicodeCategory.PrivateUse ||
                    cat == UnicodeCategory.Surrogate ||
                    cat == UnicodeCategory.SpaceSeparator ||
                    cat == UnicodeCategory.LineSeparator ||
                    cat == UnicodeCategory.ParagraphSeparator)
                    return true;

                if (ch > 0x7E)
                    return true;
            }

            return !hasAsciiLetterOrDigit;
        }
    }
}

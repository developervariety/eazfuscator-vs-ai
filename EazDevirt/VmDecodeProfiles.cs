using System.Collections.Generic;

namespace eazdevirt
{
    internal static class VmDecodeProfiles
    {
        private static readonly string[] BranchKinds = { "br", "br_family", "brtrue", "brfalse", "bcc" };

        public static VmDecodeProfile Get(string vmProfile)
        {
            var profile = (vmProfile ?? string.Empty).Trim().ToLowerInvariant();
            switch (profile)
            {
                case "custom":
                    return BuildCustom();
                case "eaz2026-default":
                case "eaz2025-default":
                default:
                    return BuildDefault();
            }
        }

        private static VmDecodeProfile BuildDefault()
        {
            var map = new Dictionary<string, int>
            {
                ["ldc_i4"] = 1,
                ["ldc.i4"] = 1,
                ["ldloc"] = 1,
                ["stloc"] = 1,
                ["ldarg"] = 1,
                ["starg"] = 1,
                ["br"] = 1,
                ["br_family"] = 1,
                ["brtrue"] = 1,
                ["brfalse"] = 1,
                ["bcc"] = 1
            };
            return new VmDecodeProfile("eaz2025-default", map, BranchKinds);
        }

        private static VmDecodeProfile BuildCustom()
        {
            // Start conservative; extend per-sample as we learn new VM rules.
            var map = new Dictionary<string, int>
            {
                ["ldc_i4"] = 1,
                ["ldc.i4"] = 1,
                ["ldloc"] = 1,
                ["stloc"] = 1,
                ["ldarg"] = 1,
                ["starg"] = 1,
                ["br"] = 1,
                ["br_family"] = 1,
                ["brtrue"] = 1,
                ["brfalse"] = 1,
                ["bcc"] = 1
            };
            return new VmDecodeProfile("custom", map, BranchKinds);
        }
    }
}

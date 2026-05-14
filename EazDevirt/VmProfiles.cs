using System;
using System.Collections.Generic;

namespace eazdevirt
{
    internal static class VmProfiles
    {
        public const string Eaz2025Default = "eaz2025-default";
        public const string Eaz2026Default = "eaz2026-default";
        public const string Custom = "custom";

        private static readonly HashSet<string> Known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Eaz2025Default,
            Eaz2026Default,
            Custom
        };

        public static string Normalize(string profile)
        {
            if (string.IsNullOrWhiteSpace(profile))
                return Eaz2025Default;
            var p = profile.Trim().ToLowerInvariant();
            return Known.Contains(p) ? p : Eaz2025Default;
        }
    }
}

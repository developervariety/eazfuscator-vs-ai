namespace eazdevirt
{
    internal static class VmDecoderFactory
    {
        public static IVmStreamDecoder Create(string profile)
        {
            // Current implementation still uses heuristic scanning, but now
            // the operand/branch decoding rules come from a profile object.
            // This is the seam for plugging in a full static decoder port.
            var decodeProfile = VmDecodeProfiles.Get(profile);
            return new HeuristicVmStreamDecoder(decodeProfile);
        }
    }
}

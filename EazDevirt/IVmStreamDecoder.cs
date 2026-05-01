using System.Collections.Generic;

namespace eazdevirt
{
    internal interface IVmStreamDecoder
    {
        string Name { get; }

        bool TryDecode(
            IReadOnlyList<byte> bytes,
            IReadOnlyDictionary<int, string> opLabelById,
            IReadOnlyList<int> preferredOpcodePrefix,
            out int startByte,
            out List<DecodedVmOp> ops);
    }
}

using System;
using System.IO;

namespace eazdevirt.V3
{
    public class CryptoStreamV3 : CryptoStreamBase
    {
        public Int32 XorKey { get; private set; }

        public CryptoStreamV3(Stream baseStream, Int32 key, Int32 xorKey)
            : base(baseStream, key ^ xorKey)
        {
            XorKey = xorKey;
        }

        protected override Byte Crypt(Byte b, Int64 position)
        {
            return (Byte)(b ^ (Byte)(Key ^ (UInt32)position));
        }
    }
}

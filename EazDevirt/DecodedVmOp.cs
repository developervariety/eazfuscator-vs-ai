namespace eazdevirt
{
    internal sealed class DecodedVmOp
    {
        public int PcBytes { get; set; }
        public int OpcodeId { get; set; }
        public string Kind { get; set; }
        public int? Operand { get; set; }
    }
}

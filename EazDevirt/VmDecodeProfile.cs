using System;
using System.Collections.Generic;

namespace eazdevirt
{
    internal sealed class VmDecodeProfile
    {
        private readonly Dictionary<string, int> _operandWordsByKind;
        private readonly HashSet<string> _branchKinds;

        public VmDecodeProfile(
            string name,
            IDictionary<string, int> operandWordsByKind,
            IEnumerable<string> branchKinds)
        {
            Name = name ?? "default";
            _operandWordsByKind = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (operandWordsByKind != null)
            {
                foreach (var kv in operandWordsByKind)
                    _operandWordsByKind[kv.Key] = kv.Value;
            }

            _branchKinds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (branchKinds != null)
            {
                foreach (var kind in branchKinds)
                    _branchKinds.Add(kind);
            }
        }

        public string Name { get; }

        public int GetOperandWords(string kind)
        {
            if (string.IsNullOrWhiteSpace(kind))
                return 0;
            return _operandWordsByKind.TryGetValue(kind, out var words) ? words : 0;
        }

        public bool IsBranchKind(string kind)
        {
            if (string.IsNullOrWhiteSpace(kind))
                return false;
            return _branchKinds.Contains(kind);
        }
    }
}

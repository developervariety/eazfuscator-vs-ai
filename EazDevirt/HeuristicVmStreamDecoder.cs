using System.Collections.Generic;

namespace eazdevirt
{
    internal sealed class HeuristicVmStreamDecoder : IVmStreamDecoder
    {
        private readonly VmDecodeProfile _profile;

        public HeuristicVmStreamDecoder(VmDecodeProfile profile)
        {
            _profile = profile;
        }

        public string Name => "heuristic-scan/" + (_profile?.Name ?? "default");

        public bool TryDecode(
            IReadOnlyList<byte> bytes,
            IReadOnlyDictionary<int, string> opLabelById,
            IReadOnlyList<int> preferredOpcodePrefix,
            out int startByte,
            out List<DecodedVmOp> ops)
        {
            ops = null;
            startByte = 0;
            if (bytes == null || bytes.Count < 8 || opLabelById == null || opLabelById.Count == 0)
                return false;

            int maxStarts = System.Math.Min(512, System.Math.Max(0, bytes.Count - 4));
            List<DecodedVmOp> best = null;
            int bestStart = 0;
            int bestPrefixHits = -1;
            for (int start = 0; start < maxStarts; start++)
            {
                foreach (var decode in BuildDecodeConfigs(bytes, start, preferredOpcodePrefix))
                {
                    var parsed = ParseAt(bytes, start, opLabelById, _profile, decode.bigEndian, decode.xorKey, decode.useXor);
                    if (parsed == null) continue;
                    int prefixHits = ScorePrefixHits(parsed, preferredOpcodePrefix);
                    if (best == null || prefixHits > bestPrefixHits || (prefixHits == bestPrefixHits && parsed.Count > best.Count))
                    {
                        best = parsed;
                        bestStart = start;
                        bestPrefixHits = prefixHits;
                    }
                }
            }
            if (best == null) return false;

            startByte = bestStart;
            ops = best;
            return true;
        }

        private static List<DecodedVmOp> ParseAt(
            IReadOnlyList<byte> bytes,
            int start,
            IReadOnlyDictionary<int, string> opLabelById,
            VmDecodeProfile profile,
            bool bigEndian,
            int xorKey,
            bool useXor)
        {
            var ops = new List<DecodedVmOp>();
            int idx = start;
            while (idx + 3 < bytes.Count)
            {
                int opcode = DecodeWord(ReadWord(bytes, idx, bigEndian), xorKey, useXor);
                if (!opLabelById.TryGetValue(opcode, out var label))
                    break;
                var (kind, idxFromLabel) = Split(label);
                int operandWords = ChooseOperandWords(bytes, idx, kind, opLabelById, profile, bigEndian, xorKey, useXor);
                int? operand = null;

                if ((kind == "ldloc" || kind == "stloc" || kind == "ldarg" || kind == "starg") && idxFromLabel.HasValue)
                {
                    operandWords = 0;
                    operand = idxFromLabel.Value;
                }
                int neededBytes = 4 + (operandWords * 4);
                if (idx + neededBytes - 1 >= bytes.Count) break;
                if (operandWords > 0)
                    operand = DecodeWord(ReadWord(bytes, idx + 4, bigEndian), xorKey, useXor);

                ops.Add(new DecodedVmOp
                {
                    PcBytes = idx - start,
                    OpcodeId = opcode,
                    Kind = kind,
                    Operand = operand
                });
                idx += neededBytes;
                if (kind == "ret") break;
            }
            return ops.Count == 0 ? null : ops;
        }

        private static int ChooseOperandWords(
            IReadOnlyList<byte> bytes,
            int idx,
            string kind,
            IReadOnlyDictionary<int, string> opLabelById,
            VmDecodeProfile profile,
            bool bigEndian,
            int xorKey,
            bool useXor)
        {
            int defaultWords = profile.GetOperandWords(kind);
            if (!profile.IsBranchKind(kind))
                return defaultWords;
            if (kind == "br" || kind == "br_family")
                return defaultWords;

            var choices = new List<int>();
            if (idx + 3 < bytes.Count) choices.Add(0);
            if (idx + 7 < bytes.Count) choices.Add(1);

            int bestWords = defaultWords;
            int bestScore = int.MinValue;
            foreach (var w in choices)
            {
                int next = idx + 4 + (w * 4);
                if (next + 3 >= bytes.Count) continue;
                int score = EstimateParseLength(bytes, next, opLabelById, profile, bigEndian, xorKey, useXor, 48);
                if (score > bestScore)
                {
                    bestScore = score;
                    bestWords = w;
                }
            }
            return bestWords;
        }

        private static int EstimateParseLength(
            IReadOnlyList<byte> bytes,
            int idx,
            IReadOnlyDictionary<int, string> opLabelById,
            VmDecodeProfile profile,
            bool bigEndian,
            int xorKey,
            bool useXor,
            int budget)
        {
            int count = 0;
            int cur = idx;
            int left = budget;
            while (left-- > 0 && cur + 3 < bytes.Count)
            {
                int opcode = DecodeWord(ReadWord(bytes, cur, bigEndian), xorKey, useXor);
                if (!opLabelById.TryGetValue(opcode, out var label)) break;
                var (kind, _) = Split(label);
                int words = profile.GetOperandWords(kind);
                int step = 4 + (words * 4);
                if (cur + step - 1 >= bytes.Count) break;
                count++;
                cur += step;
                if (kind == "ret") break;
            }
            return count;
        }

        private static (string kind, int? idx) Split(string label)
        {
            if (string.IsNullOrEmpty(label)) return ("", null);
            var lbl = label.Trim().ToLowerInvariant();
            int dot = lbl.IndexOf('.');
            if (dot < 0) return (lbl, null);
            string kind = lbl.Substring(0, dot);
            if (int.TryParse(lbl.Substring(dot + 1), out int n))
                return (kind, n);
            return (kind, null);
        }

        private static int ReadInt32(IReadOnlyList<byte> bytes, int i)
        {
            return bytes[i]
                   | (bytes[i + 1] << 8)
                   | (bytes[i + 2] << 16)
                   | (bytes[i + 3] << 24);
        }

        private static int ReadWord(IReadOnlyList<byte> bytes, int i, bool bigEndian)
        {
            if (!bigEndian)
                return ReadInt32(bytes, i);
            return (bytes[i] << 24)
                   | (bytes[i + 1] << 16)
                   | (bytes[i + 2] << 8)
                   | bytes[i + 3];
        }

        private static int DecodeWord(int rawWord, int xorKey, bool useXor)
        {
            return useXor ? (rawWord ^ xorKey) : rawWord;
        }

        private static int ScorePrefixHits(IReadOnlyList<DecodedVmOp> parsed, IReadOnlyList<int> preferredOpcodePrefix)
        {
            if (preferredOpcodePrefix == null || preferredOpcodePrefix.Count == 0 || parsed == null || parsed.Count == 0)
                return 0;
            int limit = System.Math.Min(parsed.Count, preferredOpcodePrefix.Count);
            int score = 0;
            for (int i = 0; i < limit; i++)
            {
                if (parsed[i].OpcodeId != preferredOpcodePrefix[i])
                    break;
                score++;
            }
            return score;
        }

        private static IEnumerable<(bool bigEndian, int xorKey, bool useXor)> BuildDecodeConfigs(
            IReadOnlyList<byte> bytes,
            int start,
            IReadOnlyList<int> preferredOpcodePrefix)
        {
            yield return (false, 0, false);
            yield return (true, 0, false);

            if (preferredOpcodePrefix == null || preferredOpcodePrefix.Count == 0 || start + 3 >= bytes.Count)
                yield break;

            int firstExpected = preferredOpcodePrefix[0];
            int littleRaw = ReadWord(bytes, start, false);
            int bigRaw = ReadWord(bytes, start, true);
            yield return (false, littleRaw ^ firstExpected, true);
            yield return (true, bigRaw ^ firstExpected, true);
        }
    }
}

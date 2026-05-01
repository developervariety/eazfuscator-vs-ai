using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace eazdevirt
{
    internal static class StaticCfgDevirt
    {
        public static string VmProfile { get; set; } = "eaz2025-default";

        private sealed class ParsedOp
        {
            public int PcBytes;
            public string Kind;
            public int? Operand;
        }

        public static bool TryRewrite(ModuleDefMD module, MethodDef stub, MethodTracer.TraceResult trace, out DevirtWriter.Result result, out string note)
        {
            result = new DevirtWriter.Result();
            note = "";
            bool customProfile = string.Equals(VmProfile, "custom", StringComparison.OrdinalIgnoreCase);
            if (trace?.CapturedStreamBytes == null || trace.CapturedStreamBytes.Length < 8)
            {
                note = "static-cfg: no captured stream bytes";
                return false;
            }

            var opLabelById = new Dictionary<int, string>();
            foreach (var l in trace.Lines)
            {
                if (!l.HandlerToken.HasValue) continue;
                if (string.IsNullOrEmpty(l.Label)) continue;
                if (!opLabelById.ContainsKey(l.RawValue))
                    opLabelById[l.RawValue] = l.Label;
            }
            if (opLabelById.Count == 0)
            {
                note = "static-cfg: no opcode labels";
                return false;
            }

            var readerBest = ParseFromSelectedReaderLane(trace, opLabelById, out bool readerHasRealPc);
            var decoder = VmDecoderFactory.Create(VmProfile);
            var preferredPrefix = BuildPreferredOpcodePrefix(trace, opLabelById, 24);
            int byteStart;
            List<ParsedOp> byteBest = null;
            if (decoder.TryDecode(trace.CapturedStreamBytes, opLabelById, preferredPrefix, out byteStart, out var decodedOps))
            {
                byteBest = decodedOps
                    .Select(o => new ParsedOp
                    {
                        PcBytes = o.PcBytes,
                        Kind = o.Kind,
                        Operand = o.Operand
                    })
                    .ToList();
            }
            int readerCount = readerBest?.Count ?? 0;
            int byteCount = byteBest?.Count ?? 0;
            int startByte = -1;
            var best = readerBest;
            if (byteBest != null && byteBest.Count >= 8)
            {
                best = byteBest;
                startByte = byteStart;
            }

            int minParseOps = customProfile ? 4 : 8;
            if (best == null || best.Count < minParseOps)
            {
                note = "static-cfg: parse too short";
                return false;
            }

            int repairedMissingBr = RepairMissingUnconditionalBranchOperands(best);

            int resolvedOps = trace.Lines.Count(l => l.HandlerToken.HasValue && !string.IsNullOrEmpty(l.Label));
            var expectedBranchKinds = CountBranchKinds(trace.Lines
                .Where(l => l.HandlerToken.HasValue && !string.IsNullOrEmpty(l.Label))
                .Select(l => Split(l.Label).kind));
            int expectedBranches = expectedBranchKinds.Values.Sum();
            int minNeeded = customProfile
                ? Math.Max(8, resolvedOps / 3)
                : Math.Max(16, resolvedOps / 2);
            int parsedBranchesEstimate = CountBranchKinds(best.Select(o => o.Kind)).Values.Sum();
            bool allowBranchlessLongCustom = customProfile && parsedBranchesEstimate == 0 && best.Count >= 64;
            if (best.Count < minNeeded && !allowBranchlessLongCustom)
            {
                note = $"static-cfg: parsed too few ops ({best.Count} < {minNeeded})";
                return false;
            }

            if (startByte >= 0 && expectedBranches > 0 && LooksExecutionUnrolled(best))
            {
                note = "static-cfg: byte-lane looks execution-unrolled; waiting for true CFG lane";
                return false;
            }

            var body = new CilBody { InitLocals = true, MaxStack = 16 };
            int maxLocal = best
                .Where(p => (p.Kind == "ldloc" || p.Kind == "stloc") && p.Operand.HasValue)
                .Select(p => p.Operand.Value)
                .DefaultIfEmpty(-1)
                .Max();
            for (int i = 0; i <= maxLocal; i++)
                body.Variables.Add(new Local(module.CorLibTypes.Int32));

            int argCount = stub.Parameters.Count;
            int argOffset = stub.IsStatic ? 0 : 1;

            var pcToInstruction = new Dictionary<int, Instruction>();
            var unresolvedBranches = new List<(Instruction ins, int target, int basePc, int sourcePc, int nextPc, string kind)>();
            var missingBranchOperands = new List<string>();
            int firstPcAbsolute = startByte >= 0 ? startByte : 0;
            int opsEmitted = 0;

            foreach (var op in best)
            {
                Instruction ins;
                switch (op.Kind)
                {
                    case "ldc_i4":
                    case "ldc.i4":
                        ins = Instruction.CreateLdcI4(op.Operand ?? 0);
                        break;
                    case "stloc":
                        if (op.Operand.HasValue && op.Operand.Value >= 0 && op.Operand.Value < body.Variables.Count)
                            ins = Instruction.Create(OpCodes.Stloc, body.Variables[op.Operand.Value]);
                        else
                            ins = OpCodes.Pop.ToInstruction();
                        break;
                    case "ldloc":
                        if (op.Operand.HasValue && op.Operand.Value >= 0 && op.Operand.Value < body.Variables.Count)
                            ins = Instruction.Create(OpCodes.Ldloc, body.Variables[op.Operand.Value]);
                        else
                            ins = Instruction.CreateLdcI4(0);
                        break;
                    case "starg":
                        if (op.Operand.HasValue && op.Operand.Value + argOffset < argCount)
                            ins = Instruction.Create(OpCodes.Starg, stub.Parameters[op.Operand.Value + argOffset]);
                        else
                            ins = OpCodes.Pop.ToInstruction();
                        break;
                    case "ldarg":
                        if (op.Operand.HasValue && op.Operand.Value + argOffset < argCount)
                            ins = Instruction.Create(OpCodes.Ldarg, stub.Parameters[op.Operand.Value + argOffset]);
                        else
                            ins = Instruction.CreateLdcI4(0);
                        break;
                    case "add":
                    case "binop":
                    case "binop_00":
                        ins = OpCodes.Add.ToInstruction();
                        break;
                    case "binop_10_ovf":
                        ins = OpCodes.Add_Ovf.ToInstruction();
                        break;
                    case "binop_01_un":
                    case "binop_11_ovf_un":
                        ins = OpCodes.Add_Ovf_Un.ToInstruction();
                        break;
                    case "sub": ins = OpCodes.Sub.ToInstruction(); break;
                    case "mul": ins = OpCodes.Mul.ToInstruction(); break;
                    case "div": ins = OpCodes.Div.ToInstruction(); break;
                    case "rem": ins = OpCodes.Rem.ToInstruction(); break;
                    case "and": ins = OpCodes.And.ToInstruction(); break;
                    case "or": ins = OpCodes.Or.ToInstruction(); break;
                    case "xor": ins = OpCodes.Xor.ToInstruction(); break;
                    case "shl": ins = OpCodes.Shl.ToInstruction(); break;
                    case "shr": ins = OpCodes.Shr.ToInstruction(); break;
                    case "shr_un": ins = OpCodes.Shr_Un.ToInstruction(); break;
                    case "ceq": ins = OpCodes.Ceq.ToInstruction(); break;
                    case "clt": ins = OpCodes.Clt.ToInstruction(); break;
                    case "cgt": ins = OpCodes.Cgt.ToInstruction(); break;
                    case "ret":
                        ins = OpCodes.Ret.ToInstruction();
                        break;
                    case "br":
                    case "br_family":
                        if (!op.Operand.HasValue)
                        {
                            if (missingBranchOperands.Count < 6)
                                missingBranchOperands.Add($"br@pc{op.PcBytes}");
                            ins = OpCodes.Nop.ToInstruction();
                        }
                        else
                        {
                            ins = Instruction.Create(OpCodes.Br, OpCodes.Nop.ToInstruction());
                            unresolvedBranches.Add((ins, op.Operand.Value, firstPcAbsolute, op.PcBytes, op.PcBytes + 4, "br"));
                        }
                        break;
                    case "brtrue":
                        if (!op.Operand.HasValue && missingBranchOperands.Count < 6)
                            missingBranchOperands.Add($"brtrue@pc{op.PcBytes}");
                        ins = Instruction.Create(OpCodes.Brtrue, OpCodes.Nop.ToInstruction());
                        unresolvedBranches.Add((ins, op.Operand ?? int.MinValue, firstPcAbsolute, op.PcBytes, op.PcBytes + 4, "brtrue"));
                        break;
                    case "brfalse":
                        if (!op.Operand.HasValue && missingBranchOperands.Count < 6)
                            missingBranchOperands.Add($"brfalse@pc{op.PcBytes}");
                        ins = Instruction.Create(OpCodes.Brfalse, OpCodes.Nop.ToInstruction());
                        unresolvedBranches.Add((ins, op.Operand ?? int.MinValue, firstPcAbsolute, op.PcBytes, op.PcBytes + 4, "brfalse"));
                        break;
                    case "bcc":
                        if (!op.Operand.HasValue && missingBranchOperands.Count < 6)
                            missingBranchOperands.Add($"bcc@pc{op.PcBytes}");
                        ins = Instruction.Create(OpCodes.Beq, OpCodes.Nop.ToInstruction());
                        unresolvedBranches.Add((ins, op.Operand ?? int.MinValue, firstPcAbsolute, op.PcBytes, op.PcBytes + 4, "bcc"));
                        break;
                    default:
                        ins = OpCodes.Nop.ToInstruction();
                        break;
                }

                body.Instructions.Add(ins);
                pcToInstruction[op.PcBytes] = ins;
                opsEmitted++;
            }

            int branchesTotal = unresolvedBranches.Count;
            int branchesResolved = 0;
            int condFallbacks = 0;
            int brUnknownFallbacks = 0;
            var unresolvedSamples = new List<string>();
            foreach (var br in unresolvedBranches)
            {
                if (!TryResolveTarget(pcToInstruction, br.target, br.basePc, br.sourcePc, br.nextPc, out var targetIns))
                {
                    if (br.kind == "br" && br.target == int.MinValue)
                    {
                        int idx = body.Instructions.IndexOf(br.ins);
                        if (idx >= 0 && idx + 1 < body.Instructions.Count)
                        {
                            targetIns = body.Instructions[idx + 1];
                            brUnknownFallbacks++;
                        }
                        else
                        {
                            if (unresolvedSamples.Count < 4)
                                unresolvedSamples.Add($"{br.kind}@pc{br.sourcePc}:t={br.target}");
                            continue;
                        }
                    }
                    else
                    if (br.kind == "brtrue" || br.kind == "brfalse" || br.kind == "bcc")
                    {
                        int idx = body.Instructions.IndexOf(br.ins);
                        if (idx >= 0 && idx + 1 < body.Instructions.Count)
                        {
                            targetIns = body.Instructions[idx + 1];
                            condFallbacks++;
                        }
                        else
                        {
                            if (unresolvedSamples.Count < 4)
                                unresolvedSamples.Add($"{br.kind}@pc{br.sourcePc}:t={br.target}");
                            continue;
                        }
                    }
                    else
                    {
                        if (unresolvedSamples.Count < 4)
                            unresolvedSamples.Add($"{br.kind}@pc{br.sourcePc}:t={br.target}");
                        continue;
                    }
                }
                br.ins.Operand = targetIns;
                branchesResolved++;
            }

            if (branchesTotal > 0 && branchesResolved < branchesTotal)
            {
                string extra = unresolvedSamples.Count > 0 ? $" [{string.Join(", ", unresolvedSamples)}]" : "";
                note = $"static-cfg: unresolved branches ({branchesResolved}/{branchesTotal}){extra}";
                return false;
            }

            if (expectedBranches > 0 && branchesTotal < expectedBranches)
            {
                int gap = expectedBranches - branchesTotal;
                int allowedGap = customProfile ? (best.Count >= 64 ? 5 : 2) : 0;
                if (customProfile && gap <= allowedGap)
                {
                    // Custom VM profiles can expose one branch-family delta due to
                    // decoder lane drift; allow this as long as all parsed branches resolved.
                }
                else
                {
                var parsedBranchKinds = CountBranchKinds(best.Select(o => o.Kind));
                string delta = DescribeBranchDelta(expectedBranchKinds, parsedBranchKinds);
                string miss = missingBranchOperands.Count > 0 ? $" missing-operand=[{string.Join(", ", missingBranchOperands)}]" : "";
                note = $"static-cfg: parsed branch undercount ({branchesTotal} < {expectedBranches}){delta}{miss}";
                return false;
                }
            }

            if (brUnknownFallbacks > 0)
            {
                note = $"static-cfg: unknown unconditional branch targets ({brUnknownFallbacks})";
                return false;
            }

            if (startByte < 0 && branchesTotal > 0 && !customProfile)
            {
                note = $"static-cfg: opcode-reader lane contains branches; waiting for byte-lane PC parse (byte={byteCount}@{byteStart}, reader={readerCount})";
                return false;
            }

            if (body.Instructions.Count == 0 || body.Instructions[body.Instructions.Count - 1].OpCode.Code != Code.Ret)
                body.Instructions.Add(OpCodes.Ret.ToInstruction());

            stub.FreeMethodBody();
            stub.Body = body;
            body.UpdateInstructionOffsets();

            result.OpsEmitted = opsEmitted;
            result.LocalsDeclared = body.Variables.Count;
            result.UsedStaticCfg = true;
            result.BranchesTotal = branchesTotal;
            result.BranchesResolved = branchesResolved;
            string lane = startByte >= 0 ? $"byte-lane@{startByte}" : "opcode-reader-lane";
            result.RewriteNote = $"static-cfg[{VmProfile}]: {lane}, parsed={best.Count}, branch-resolve={branchesResolved}/{branchesTotal}, repaired-br={repairedMissingBr}, cond-fallback={condFallbacks}, br-unknown-fallback={brUnknownFallbacks}";
            return true;
        }

        private static List<int> BuildPreferredOpcodePrefix(
            MethodTracer.TraceResult trace,
            IReadOnlyDictionary<int, string> opLabelById,
            int maxCount)
        {
            var prefix = new List<int>();
            if (trace?.RawIntReads == null || trace.RawIntReads.Count == 0 || !trace.SelectedOpcodeReaderToken.HasValue)
                return prefix;

            uint token = trace.SelectedOpcodeReaderToken.Value;
            foreach (var ev in trace.RawIntReads)
            {
                if (ev.MethodToken != token)
                    continue;
                if (!opLabelById.ContainsKey(ev.RawValue))
                    continue;
                prefix.Add(ev.RawValue);
                if (prefix.Count >= maxCount)
                    break;
            }

            return prefix;
        }

        private static List<ParsedOp> ParseFromSelectedReaderLane(
            MethodTracer.TraceResult trace,
            IReadOnlyDictionary<int, string> opLabelById,
            out bool hasRealPc)
        {
            hasRealPc = false;
            if (trace?.RawIntReads == null || trace.RawIntReads.Count == 0) return null;
            // Require that tracing selected a dominant opcode reader.
            if (!trace.SelectedOpcodeReaderToken.HasValue) return null;
            uint selectedToken = trace.SelectedOpcodeReaderToken.Value;
            int selectedWithPos = trace.RawIntReads.Count(r =>
                r.MethodToken == selectedToken && (r.StreamPosBefore >= 0 || r.StreamPosAfter >= 0));
            long firstPos = -1;
            for (int fi = 0; fi < trace.RawIntReads.Count; fi++)
            {
                var first = trace.RawIntReads[fi];
                if (first.MethodToken == selectedToken && first.StreamPosBefore >= 0)
                {
                    firstPos = first.StreamPosBefore;
                    break;
                }
            }
            if (firstPos < 0)
            {
                for (int fi = 0; fi < trace.RawIntReads.Count; fi++)
                {
                    var first = trace.RawIntReads[fi];
                    if (first.MethodToken != selectedToken) continue;
                    var approx = ResolveApproxStreamPos(trace.RawIntReads, fi);
                    if (approx >= 0) { firstPos = approx; break; }
                }
            }

            var ops = new List<ParsedOp>();
            int positionedOps = 0;
            int i = 0;
            while (i < trace.RawIntReads.Count)
            {
                var ev = trace.RawIntReads[i];
                if (ev.MethodToken != selectedToken)
                {
                    i++;
                    continue;
                }

                int raw = ev.RawValue;
                if (!opLabelById.TryGetValue(raw, out var label) || string.IsNullOrEmpty(label))
                {
                    i++;
                    continue;
                }

                var (kind, idxFromLabel) = Split(label);
                int need = OperandWords(kind);
                int? operand = null;

                // Label suffix is a reliable operand only for indexed locals/args.
                if (kind == "ldloc" || kind == "stloc" || kind == "ldarg" || kind == "starg")
                {
                    operand = idxFromLabel;
                    if (operand.HasValue) need = 0;
                }
                if (need > 0)
                {
                    int words = 0;
                    int j = i + 1;
                    while (j < trace.RawIntReads.Count && words < need)
                    {
                        var nextEv = trace.RawIntReads[j];
                        bool isNextOpcode = nextEv.MethodToken == selectedToken &&
                                            opLabelById.ContainsKey(nextEv.RawValue);
                        if (isNextOpcode)
                            break;

                        if (words == 0)
                            operand = nextEv.RawValue;
                        words++;
                        j++;
                    }
                    if (words < need)
                    {
                        if (IsBranchKind(kind))
                            operand = null;
                        else
                            break;
                    }
                }

                long approxPos = ResolveApproxStreamPos(trace.RawIntReads, i);
                ops.Add(new ParsedOp
                {
                    // Keep reader-lane PCs synthetic/stable; stream positions are
                    // currently used as confidence signals, not direct CFG offsets.
                    PcBytes = ops.Count * 4,
                    Kind = kind,
                    Operand = operand
                });
                if (approxPos >= 0 && firstPos >= 0)
                    positionedOps++;
                i++;
                if (kind == "ret") break;
            }

            hasRealPc = positionedOps >= 4 || selectedWithPos >= 4;
            return ops.Count == 0 ? null : ops;
        }

        private static List<ParsedOp> FindBestParse(IReadOnlyList<byte> bytes, IReadOnlyDictionary<int, string> opLabelById, out int bestStart)
        {
            List<ParsedOp> best = null;
            bestStart = 0;
            int maxStarts = Math.Min(512, Math.Max(0, bytes.Count - 4));
            for (int start = 0; start < maxStarts; start++)
            {
                var parsed = ParseAt(bytes, start, opLabelById);
                if (parsed == null) continue;
                if (best == null || parsed.Count > best.Count)
                {
                    best = parsed;
                    bestStart = start;
                }
            }
            return best;
        }

        private static List<ParsedOp> ParseAt(IReadOnlyList<byte> bytes, int start, IReadOnlyDictionary<int, string> opLabelById)
        {
            var ops = new List<ParsedOp>();
            int idx = start;
            while (idx + 3 < bytes.Count)
            {
                int opcode = ReadInt32(bytes, idx);
                if (!opLabelById.TryGetValue(opcode, out var label))
                    break;
                var (kind, idxFromLabel) = Split(label);
                int operandWords = ChooseOperandWords(bytes, idx, kind, opLabelById);
                int? operand = null;

                // Some families encode local/arg index directly in the opcode ID label.
                // Avoid consuming phantom inline operands in that case.
                if ((kind == "ldloc" || kind == "stloc" || kind == "ldarg" || kind == "starg") && idxFromLabel.HasValue)
                {
                    operandWords = 0;
                    operand = idxFromLabel.Value;
                }
                int neededBytes = 4 + (operandWords * 4);
                if (idx + neededBytes - 1 >= bytes.Count) break;
                if (operandWords > 0)
                {
                    int oi = idx + 4;
                    operand = ReadInt32(bytes, oi);
                }
                ops.Add(new ParsedOp
                {
                    PcBytes = idx - start,
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
            IReadOnlyDictionary<int, string> opLabelById)
        {
            int defaultWords = OperandWords(kind);
            if (!IsBranchKind(kind))
                return defaultWords;
            if (kind == "br" || kind == "br_family")
                return defaultWords;

            var choices = new List<int>();
            if (idx + 3 < bytes.Count)
                choices.Add(0);
            if (idx + 7 < bytes.Count)
                choices.Add(1);

            int bestWords = defaultWords;
            int bestScore = int.MinValue;
            foreach (var w in choices)
            {
                int next = idx + 4 + (w * 4);
                if (next + 3 >= bytes.Count)
                    continue;
                int score = EstimateParseLength(bytes, next, opLabelById, 48);
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
            int budget)
        {
            int count = 0;
            int cur = idx;
            int left = budget;
            while (left-- > 0 && cur + 3 < bytes.Count)
            {
                int opcode = ReadInt32(bytes, cur);
                if (!opLabelById.TryGetValue(opcode, out var label))
                    break;
                var (kind, _) = Split(label);
                int words = OperandWords(kind);
                int step = 4 + (words * 4);
                if (cur + step - 1 >= bytes.Count)
                    break;
                count++;
                cur += step;
                if (kind == "ret")
                    break;
            }
            return count;
        }

        private static bool TryResolveTarget(
            IReadOnlyDictionary<int, Instruction> pcToInstruction,
            int rawTarget,
            int basePc,
            int sourcePc,
            int nextPc,
            out Instruction target)
        {
            target = null;
            if (rawTarget == int.MinValue) return false;

            var candidates = new[]
            {
                rawTarget,
                rawTarget - basePc,
                rawTarget + basePc,
                rawTarget - sourcePc,
                rawTarget + sourcePc,
                rawTarget - nextPc,
                rawTarget + nextPc,
                sourcePc + rawTarget,
                nextPc + rawTarget,
                sourcePc - rawTarget,
                nextPc - rawTarget,
                rawTarget * 4,
                (rawTarget * 4) - basePc
                ,
                (rawTarget * 4) + basePc,
                (rawTarget * 4) - sourcePc,
                (rawTarget * 4) + sourcePc,
                (rawTarget * 4) - nextPc,
                (rawTarget * 4) + nextPc,
                sourcePc + (rawTarget * 4),
                nextPc + (rawTarget * 4),
                sourcePc - (rawTarget * 4),
                nextPc - (rawTarget * 4)
            };
            foreach (var c in candidates)
            {
                if (pcToInstruction.TryGetValue(c, out target))
                    return true;
            }
            return false;
        }

        private static int OperandWords(string kind)
        {
            switch (kind)
            {
                case "ldc_i4":
                case "ldc.i4":
                case "ldloc":
                case "stloc":
                case "ldarg":
                case "starg":
                case "br":
                case "br_family":
                case "brtrue":
                case "brfalse":
                case "bcc":
                    return 1;
                default:
                    return 0;
            }
        }

        private static bool IsBranchKind(string kind)
        {
            return kind == "br"
                   || kind == "br_family"
                   || kind == "brtrue"
                   || kind == "brfalse"
                   || kind == "bcc";
        }

        private static int RepairMissingUnconditionalBranchOperands(List<ParsedOp> ops)
        {
            if (ops == null || ops.Count == 0) return 0;
            int repaired = 0;
            for (int i = 0; i < ops.Count; i++)
            {
                var op = ops[i];
                if ((op.Kind != "br" && op.Kind != "br_family") || op.Operand.HasValue)
                    continue;

                // For pre-header style unconditional branches with hidden targets,
                // the next conditional checkpoint is usually the loop/test block.
                ParsedOp target = null;
                for (int j = i + 1; j < ops.Count; j++)
                {
                    var k = ops[j].Kind;
                    if (k == "brtrue" || k == "brfalse" || k == "bcc")
                    {
                        target = ops[j];
                        break;
                    }
                }

                if (target == null && i + 1 < ops.Count)
                    target = ops[i + 1];
                if (target == null)
                    continue;

                op.Operand = target.PcBytes;
                repaired++;
            }
            return repaired;
        }

        private static bool LooksExecutionUnrolled(IReadOnlyList<ParsedOp> ops)
        {
            if (ops == null || ops.Count < 24) return false;

            // Detect a repeated contiguous opcode-kind slice (classic loop-unrolled trace shape).
            for (int win = 6; win <= 14; win++)
            {
                int maxStart = ops.Count - (win * 3);
                for (int s = 0; s <= maxStart; s++)
                {
                    bool same1 = true, same2 = true;
                    for (int i = 0; i < win; i++)
                    {
                        if (ops[s + i].Kind != ops[s + win + i].Kind) same1 = false;
                        if (ops[s + i].Kind != ops[s + (win * 2) + i].Kind) same2 = false;
                        if (!same1 && !same2) break;
                    }
                    if (same1 && same2)
                        return true;
                }
            }
            return false;
        }

        private static Dictionary<string, int> CountBranchKinds(IEnumerable<string> kinds)
        {
            var map = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var k in kinds)
            {
                if (!IsBranchKind(k)) continue;
                if (!map.TryGetValue(k, out var n)) n = 0;
                map[k] = n + 1;
            }
            return map;
        }

        private static string DescribeBranchDelta(
            IReadOnlyDictionary<string, int> expected,
            IReadOnlyDictionary<string, int> parsed)
        {
            var parts = new List<string>();
            foreach (var kv in expected.OrderBy(k => k.Key))
            {
                parsed.TryGetValue(kv.Key, out var got);
                if (got != kv.Value)
                    parts.Add($"{kv.Key}:{got}/{kv.Value}");
            }
            return parts.Count == 0 ? "" : $" [{string.Join(", ", parts)}]";
        }

        private static long ResolveApproxStreamPos(IReadOnlyList<MethodTracer.IntReadEvent> reads, int idx)
        {
            if (reads == null || idx < 0 || idx >= reads.Count) return -1;
            long direct = GetBestPos(reads[idx]);
            if (direct >= 0) return direct;

            const int scan = 6;
            for (int d = 1; d <= scan; d++)
            {
                int back = idx - d;
                if (back >= 0)
                {
                    long bp = GetBestPos(reads[back]);
                    if (bp >= 0) return bp + (d * 4L);
                }

                int fwd = idx + d;
                if (fwd < reads.Count)
                {
                    long fp = GetBestPos(reads[fwd]);
                    if (fp >= 0) return Math.Max(0, fp - (d * 4L));
                }
            }
            return -1;
        }

        private static long GetBestPos(MethodTracer.IntReadEvent ev)
        {
            if (ev == null) return -1;
            if (ev.StreamPosBefore >= 0) return ev.StreamPosBefore;
            if (ev.StreamPosAfter >= 0) return ev.StreamPosAfter;
            return -1;
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
                   | (bytes[i + 3] << 24)
                   | (bytes[i + 1] << 16)
                   | (bytes[i + 2] << 8);
        }
    }
}

using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace eazdevirt
{
    /// <summary>
    /// Takes a method-execution trace (sequence of classifier labels) and
    /// rewrites a VM stub's body into equivalent-ish CIL.
    ///
    /// Limitations — this is DYNAMIC devirt; the output reflects the
    /// specific execution path captured by the trace, not the full static
    /// structure of the original method:
    ///
    /// - Branches (br/brtrue/brfalse/bcc) become `nop` (fall-through). A
    ///   trace of a looped method WILL unroll the executed iterations into
    ///   straight-line CIL.
    /// - Unclassified primitives become `nop /* comment */`.
    /// - Binop flavors default to `add` (signed unchecked). The classifier
    ///   tells us the signed/unsigned/checked flags; we can't tell add vs
    ///   sub vs mul without deeper analysis.
    /// - Ldc_I4 values come from the stub trace's operand stream; we don't
    ///   have them yet, so we emit ldc.i4.0 as a placeholder. Future work
    ///   can correlate trace operand reads with ldc opcodes.
    ///
    /// What you get: a method body that dnSpy can parse and that shows the
    /// rough shape of the devirtualized method — arguments loaded, locals
    /// stored, arithmetic, loop structure (unrolled), return. Enough to
    /// understand what the method does for forensic purposes.
    /// </summary>
    public static class DevirtWriter
    {
        public static string VmProfile { get; set; } = "eaz2025-default";

        public sealed class Result
        {
            public int OpsEmitted;
            public int LocalsDeclared;
            public bool UsedStaticCfg;
            public int BranchesTotal;
            public int BranchesResolved;
            public string RewriteNote;
            public string ErrorMessage;
        }

        public static Result Rewrite(ModuleDefMD module, uint stubToken, MethodTracer.TraceResult trace, bool foldLoops = true)
        {
            var r = new Result();
            var stub = module.ResolveMethod(stubToken & 0xFFFFFF) as MethodDef;
            if (stub == null) { r.ErrorMessage = "stub method not found"; return r; }

            // First try static parsing from captured decrypted stream bytes.
            // If it fails, fall back to the legacy trace-unroll writer.
            StaticCfgDevirt.VmProfile = VmProfile;
            if (StaticCfgDevirt.TryRewrite(module, stub, trace, out var staticCfg, out var staticNote))
                return staticCfg;

            var allLines = trace.Lines.Where(l => l.HandlerToken.HasValue && !string.IsNullOrEmpty(l.Label)).ToList();
            if (allLines.Count == 0) { r.ErrorMessage = "trace contains no classified ops"; return r; }

            // Optionally detect a single back-to-back repetition loop and
            // emit a real `br loop_head` structure, so the rewritten method
            // preserves iteration rather than unrolling it linearly.
            LoopDetector.Folded folded = null;
            if (foldLoops)
            {
                folded = LoopDetector.Fold(trace);
                if (folded.Iterations < 2) folded = null;
            }

            var emitLines = folded != null
                ? folded.Prefix.Concat(folded.Body).Concat(folded.Suffix).ToList()
                : allLines;

            int maxLocalIdx = -1;
            foreach (var l in emitLines)
            {
                var (kind, idx) = Split(l.Label);
                if ((kind == "stloc" || kind == "ldloc") && idx.HasValue && idx.Value > maxLocalIdx)
                    maxLocalIdx = idx.Value;
            }

            var body = new CilBody { InitLocals = true, MaxStack = 16 };
            var sigInt32 = module.CorLibTypes.Int32;
            for (int i = 0; i <= maxLocalIdx; i++)
                body.Variables.Add(new Local(sigInt32));
            Local loopCounter = null;
            if (folded != null)
            {
                loopCounter = new Local(sigInt32);
                body.Variables.Add(loopCounter);
            }
            r.LocalsDeclared = body.Variables.Count;

            int argCount = stub.Parameters.Count;  // includes `this` for instance
            int argOffset = stub.IsStatic ? 0 : 1;

            // Track the first body instruction position so we can wire a
            // `br loop_head` back to it after the body.
            int bodyStartIdx = folded?.Prefix.Count ?? -1;
            int opsEmitted = 0;
            Instruction loopHead = null;
            for (int lineIdx = 0; lineIdx < emitLines.Count; lineIdx++)
            {
                var l = emitLines[lineIdx];
                var (kind, idx) = Split(l.Label);
                Instruction ins = null;

                switch (kind)
                {
                    case "ldc_i4":
                    case "ldc.i4":
                        // The classifier preserved the integer value in the
                        // idx component: "Ldc_I4.5" -> idx = 5. This is the
                        // constant baked into the handler's own IL (ldc.i4.N;
                        // callvirt primitive(N)), so it's ground-truth for
                        // pre-packed opcodes. For the generic "read N from
                        // stream" opcode we'd need operand-stream correlation;
                        // not implemented yet, default to 0 when idx missing.
                        ins = Instruction.CreateLdcI4(idx ?? 0);
                        break;

                    case "stloc":
                        if (idx.HasValue && idx.Value < body.Variables.Count)
                            ins = Instruction.Create(OpCodes.Stloc, body.Variables[idx.Value]);
                        else
                            ins = OpCodes.Pop.ToInstruction();
                        break;
                    case "ldloc":
                        if (idx.HasValue && idx.Value < body.Variables.Count)
                            ins = Instruction.Create(OpCodes.Ldloc, body.Variables[idx.Value]);
                        else
                            ins = Instruction.CreateLdcI4(0);
                        break;
                    case "starg":
                        if (idx.HasValue && idx.Value + argOffset < argCount)
                            ins = Instruction.Create(OpCodes.Starg, stub.Parameters[idx.Value + argOffset]);
                        else
                            ins = OpCodes.Pop.ToInstruction();
                        break;
                    case "ldarg":
                        if (idx.HasValue && idx.Value + argOffset < argCount)
                            ins = Instruction.Create(OpCodes.Ldarg, stub.Parameters[idx.Value + argOffset]);
                        else
                            ins = Instruction.CreateLdcI4(0);
                        break;

                    case "ret":
                        ins = OpCodes.Ret.ToInstruction();
                        break;
                    case "br":
                    case "br_family":
                    case "brtrue":
                    case "brfalse":
                    case "bcc":
                        // No static branch target — emit a nop and let the
                        // trace continue with the next traced op.
                        ins = OpCodes.Nop.ToInstruction();
                        break;

                    case "add":
                    case "binop":
                    case "binop_00":
                        ins = OpCodes.Add.ToInstruction(); break;
                    case "binop_10_ovf":
                        ins = OpCodes.Add_Ovf.ToInstruction(); break;
                    case "binop_01_un":
                    case "binop_11_ovf_un":
                        ins = OpCodes.Add_Ovf_Un.ToInstruction(); break;
                    case "sub": ins = OpCodes.Sub.ToInstruction(); break;
                    case "mul": ins = OpCodes.Mul.ToInstruction(); break;
                    case "div": ins = OpCodes.Div.ToInstruction(); break;
                    case "rem": ins = OpCodes.Rem.ToInstruction(); break;
                    case "and": ins = OpCodes.And.ToInstruction(); break;
                    case "or":  ins = OpCodes.Or.ToInstruction(); break;
                    case "xor": ins = OpCodes.Xor.ToInstruction(); break;
                    case "shl": ins = OpCodes.Shl.ToInstruction(); break;
                    case "shr": ins = OpCodes.Shr.ToInstruction(); break;
                    case "shr_un": ins = OpCodes.Shr_Un.ToInstruction(); break;
                    case "ceq": ins = OpCodes.Ceq.ToInstruction(); break;
                    case "clt": ins = OpCodes.Clt.ToInstruction(); break;
                    case "cgt": ins = OpCodes.Cgt.ToInstruction(); break;
                    case "pop": ins = OpCodes.Pop.ToInstruction(); break;

                    default:
                        // Unknown or VM-internal op (stateget, Prim_0x...) —
                        // emit nop so the body is still valid.
                        ins = OpCodes.Nop.ToInstruction();
                        break;
                }

                if (ins != null)
                {
                    body.Instructions.Add(ins);
                    if (folded != null && lineIdx == bodyStartIdx && loopHead == null)
                        loopHead = ins;
                    opsEmitted++;
                }
            }

            // Replace fragile back-edge logic with a deterministic counted loop:
            //   counter = traced-iterations;
            // loop_head:
            //   body...
            //   counter = counter - 1;
            //   if (counter > 0) br loop_head;
            // This preserves observed iteration count while avoiding infinite
            // loops when branch targets are unavailable.
            if (folded != null && loopHead != null && folded.Body.Count > 0)
            {
                int loopStartIndex = bodyStartIdx;
                body.Instructions.Insert(loopStartIndex, Instruction.CreateLdcI4(folded.Iterations));
                body.Instructions.Insert(loopStartIndex + 1, Instruction.Create(OpCodes.Stloc, loopCounter));

                int loopTailIndex = loopStartIndex + 2 + folded.Body.Count;
                body.Instructions.Insert(loopTailIndex++, Instruction.Create(OpCodes.Ldloc, loopCounter));
                body.Instructions.Insert(loopTailIndex++, Instruction.CreateLdcI4(1));
                body.Instructions.Insert(loopTailIndex++, OpCodes.Sub.ToInstruction());
                body.Instructions.Insert(loopTailIndex++, OpCodes.Dup.ToInstruction());
                body.Instructions.Insert(loopTailIndex++, Instruction.Create(OpCodes.Stloc, loopCounter));
                body.Instructions.Insert(loopTailIndex++, Instruction.CreateLdcI4(0));
                body.Instructions.Insert(loopTailIndex++, OpCodes.Cgt.ToInstruction());
                body.Instructions.Insert(loopTailIndex, Instruction.Create(OpCodes.Brtrue, loopHead));
                opsEmitted += 10;
            }

            // Ensure terminating ret.
            if (body.Instructions.Count == 0 || body.Instructions[body.Instructions.Count - 1].OpCode.Code != Code.Ret)
            {
                var rt = stub.ReturnType?.FullName ?? "System.Void";
                if (rt != "System.Void")
                {
                    // Return type mismatch — emit a default value push before ret.
                    if (rt == "System.Int64")
                        body.Instructions.Add(OpCodes.Ldc_I8.ToInstruction((long)0));
                    else if (rt == "System.Single")
                        body.Instructions.Add(OpCodes.Ldc_R4.ToInstruction(0f));
                    else if (rt == "System.Double")
                        body.Instructions.Add(OpCodes.Ldc_R8.ToInstruction(0d));
                    else if (rt == "System.String")
                        body.Instructions.Add(OpCodes.Ldstr.ToInstruction(""));
                    else if (stub.ReturnType?.IsValueType == true)
                    {
                        // Fall back to default int for unknown value types
                        body.Instructions.Add(Instruction.CreateLdcI4(0));
                    }
                    else
                        body.Instructions.Add(OpCodes.Ldnull.ToInstruction());
                }
                body.Instructions.Add(OpCodes.Ret.ToInstruction());
            }

            stub.FreeMethodBody();
            stub.Body = body;
            body.UpdateInstructionOffsets();

            r.OpsEmitted = opsEmitted;
            r.UsedStaticCfg = false;
            if (folded != null && folded.Iterations >= 2)
                r.RewriteNote = $"trace-fold: body={folded.Body.Count}, iters={folded.Iterations}; {staticNote}";
            else
                r.RewriteNote = staticNote;
            return r;
        }

        private static (string kind, int? idx) Split(string label)
        {
            if (string.IsNullOrEmpty(label)) return ("", null);
            // Strip any leading comment noise.
            var lbl = label.Trim().ToLowerInvariant();
            int dot = lbl.IndexOf('.');
            if (dot < 0) return (lbl, null);
            string kind = lbl.Substring(0, dot);
            if (int.TryParse(lbl.Substring(dot + 1), out int n))
                return (kind, n);
            return (kind, null);
        }
    }
}

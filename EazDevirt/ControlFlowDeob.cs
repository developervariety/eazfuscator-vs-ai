using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace eazdevirt
{
    /// <summary>
    /// Simple control-flow deobfuscator targeting Eazfuscator's boolean-constant
    /// cflow pattern:
    ///
    ///   ldc.i4 &lt;const&gt; ; brtrue.s target ; pop ; pop ; br.s dead
    ///
    /// The constant is known at compile time so one of the two paths is dead.
    /// We replace the pair (ldc + branch) with either an unconditional branch
    /// to the taken target (and leave the subsequent dead code for dnlib's
    /// dead-code removal) or a pair of nops (fall through).
    ///
    /// We also handle the inverse pattern `ldc.i4 0 ; brtrue` (never taken,
    /// becomes nop pair) and `ldc.i4 N (N != 0) ; brfalse` (never taken,
    /// becomes nop pair) plus their always-taken siblings.
    ///
    /// Applies iteratively per method until stable. Returns the number of
    /// transforms performed across the module.
    /// </summary>
    public static class ControlFlowDeob
    {
        public sealed class Result
        {
            public int MethodsTouched;
            public int TotalTransforms;
            public int MethodsSkipped;
            public List<string> Failures = new List<string>();
        }

        public static Result Run(ModuleDefMD module)
        {
            var r = new Result();
            foreach (var t in module.GetTypes())
            {
                foreach (var m in t.Methods)
                {
                    if (m.Body == null || !m.Body.HasInstructions) continue;
                    int n;
                    try { n = DeobfuscateMethod(m); }
                    catch (Exception ex)
                    {
                        r.Failures.Add($"{t.FullName}.{m.Name}: {ex.Message}");
                        r.MethodsSkipped++;
                        continue;
                    }
                    if (n > 0)
                    {
                        r.MethodsTouched++;
                        r.TotalTransforms += n;
                    }
                }
            }
            return r;
        }

        /// <summary>
        /// Apply const-br-const cleanup iteratively to a single method body.
        /// </summary>
        public static int DeobfuscateMethod(MethodDef method)
        {
            var body = method.Body;
            int totalTransforms = 0;
            bool changed = true;
            int guard = 256;
            while (changed && guard-- > 0)
            {
                changed = false;
                var instrs = body.Instructions;
                for (int i = 0; i < instrs.Count - 1; i++)
                {
                    var a = instrs[i];
                    var b = instrs[i + 1];
                    if (!a.IsLdcI4()) continue;
                    int cst = a.GetLdcI4Value();

                    Code c = b.OpCode.Code;
                    bool isBrtrue = c == Code.Brtrue || c == Code.Brtrue_S;
                    bool isBrfalse = c == Code.Brfalse || c == Code.Brfalse_S;
                    if (!isBrtrue && !isBrfalse) continue;

                    bool taken = isBrtrue ? (cst != 0) : (cst == 0);
                    var target = b.Operand as Instruction;

                    // Mutate the instructions in-place so any existing
                    // branch targets / EH refs pointing at them remain valid.
                    if (taken)
                    {
                        // (ldc.i4 cst; br<cond> tgt) -> (nop; br tgt)
                        a.OpCode = OpCodes.Nop;
                        a.Operand = null;
                        b.OpCode = OpCodes.Br;
                        b.Operand = target;
                    }
                    else
                    {
                        a.OpCode = OpCodes.Nop;
                        a.Operand = null;
                        b.OpCode = OpCodes.Nop;
                        b.Operand = null;
                    }

                    totalTransforms++;
                    changed = true;
                    i++; // skip the consumed branch
                }
            }

            // After transforms, run a small peephole pass to remove unreachable
            // dead code BETWEEN an unconditional br and the next instruction
            // that's actually targeted by something.
            if (totalTransforms > 0)
                RemoveObviouslyDead(method);

            totalTransforms += RemoveNonTargetNops(method);

            // Recompute offsets + optimize branches (turn `br` into `br.s`
            // where possible). If we introduced `br` instances that can't be
            // short-formed, they stay as long branches.
            body.UpdateInstructionOffsets();
            try { body.OptimizeBranches(); } catch { /* keep long branches */ }
            return totalTransforms;
        }

        /// <summary>
        /// After inserting unconditional brs, instructions after them that
        /// aren't branch targets become unreachable. Replace with nop.
        /// Note: we don't REMOVE instructions (that would break operand
        /// referential integrity); we just nop them.
        /// </summary>
        private static void RemoveObviouslyDead(MethodDef method)
        {
            var body = method.Body;
            var instrs = body.Instructions;

            // Collect all branch targets plus exception-handler entry points.
            var targets = new HashSet<Instruction>();
            foreach (var ins in instrs)
            {
                if (ins.Operand is Instruction t)
                    targets.Add(t);
                else if (ins.Operand is Instruction[] arr)
                    foreach (var t2 in arr) targets.Add(t2);
            }
            foreach (var eh in body.ExceptionHandlers)
            {
                if (eh.TryStart != null) targets.Add(eh.TryStart);
                if (eh.TryEnd != null) targets.Add(eh.TryEnd);
                if (eh.HandlerStart != null) targets.Add(eh.HandlerStart);
                if (eh.HandlerEnd != null) targets.Add(eh.HandlerEnd);
                if (eh.FilterStart != null) targets.Add(eh.FilterStart);
            }

            bool unreachable = false;
            for (int i = 0; i < instrs.Count; i++)
            {
                var ins = instrs[i];
                if (targets.Contains(ins)) unreachable = false;

                if (unreachable)
                {
                    if (ins.OpCode.Code != Code.Nop)
                    {
                        ins.OpCode = OpCodes.Nop;
                        ins.Operand = null;
                    }
                    continue;
                }

                var c = ins.OpCode.Code;
                if (c == Code.Br || c == Code.Br_S
                    || c == Code.Ret || c == Code.Throw
                    || c == Code.Rethrow || c == Code.Endfinally
                    || c == Code.Endfilter || c == Code.Leave
                    || c == Code.Leave_S)
                    unreachable = true;
            }
        }

        private static int RemoveNonTargetNops(MethodDef method)
        {
            var body = method.Body;
            var instrs = body.Instructions;
            var anchors = new HashSet<Instruction>();

            foreach (var ins in instrs)
            {
                if (ins.Operand is Instruction target)
                    anchors.Add(target);
                else if (ins.Operand is Instruction[] targets)
                    foreach (var t in targets)
                        anchors.Add(t);
            }

            foreach (var eh in body.ExceptionHandlers)
            {
                if (eh.TryStart != null) anchors.Add(eh.TryStart);
                if (eh.TryEnd != null) anchors.Add(eh.TryEnd);
                if (eh.HandlerStart != null) anchors.Add(eh.HandlerStart);
                if (eh.HandlerEnd != null) anchors.Add(eh.HandlerEnd);
                if (eh.FilterStart != null) anchors.Add(eh.FilterStart);
            }

            int removed = 0;
            for (int i = instrs.Count - 1; i >= 0; i--)
            {
                var ins = instrs[i];
                if (ins.OpCode.Code != Code.Nop)
                    continue;
                if (anchors.Contains(ins))
                    continue;
                instrs.RemoveAt(i);
                removed++;
            }
            return removed;
        }
    }
}

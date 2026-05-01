using System;
using System.Collections.Generic;
using System.Linq;

namespace eazdevirt
{
    /// <summary>
    /// Post-processes a MethodTracer.TraceResult to fold consecutive
    /// repetitions of an opcode subsequence back into a loop.
    ///
    /// Input: linear trace where a loop with N iterations shows as N copies
    /// of the body subsequence, back-to-back.
    /// Output: [prefix][body(once, marked as loop body)][suffix]
    ///         + metadata that the DevirtWriter can consume to emit a
    ///         `br loop_body` instead of just dropping the repetition.
    ///
    /// This is heuristic — it only handles the simplest case of back-to-back
    /// repetition of a single subsequence. Nested/interleaved loops need
    /// more work.
    /// </summary>
    public static class LoopDetector
    {
        public sealed class Folded
        {
            public List<MethodTracer.TraceLine> Prefix { get; } = new List<MethodTracer.TraceLine>();
            public List<MethodTracer.TraceLine> Body { get; } = new List<MethodTracer.TraceLine>();
            public List<MethodTracer.TraceLine> Suffix { get; } = new List<MethodTracer.TraceLine>();
            public int Iterations;
        }

        public static Folded Fold(MethodTracer.TraceResult trace)
        {
            var lines = trace.Lines.Where(l => l.HandlerToken.HasValue).ToList();
            var result = new Folded();

            // Try body lengths from 1 to lines.Count/2. Pick the longest
            // length at which we find >= 2 consecutive repetitions of some
            // subsequence. Prefer more repetitions over longer bodies.
            int bestStart = -1, bestLen = 0, bestIters = 0;
            for (int len = 1; len <= lines.Count / 2; len++)
            {
                for (int start = 0; start <= lines.Count - 2 * len; start++)
                {
                    int iters = CountRepetitions(lines, start, len);
                    if (iters < 2) continue;
                    // Score: prefer more iterations, break ties by longer body.
                    int thisScore = iters * 1000 + len;
                    int bestScore = bestIters * 1000 + bestLen;
                    if (thisScore > bestScore)
                    {
                        bestStart = start;
                        bestLen = len;
                        bestIters = iters;
                    }
                }
            }

            if (bestIters < 2)
            {
                // No loop detected — everything is prefix.
                result.Prefix.AddRange(lines);
                return result;
            }

            for (int i = 0; i < bestStart; i++) result.Prefix.Add(lines[i]);
            for (int i = bestStart; i < bestStart + bestLen; i++) result.Body.Add(lines[i]);
            for (int i = bestStart + bestIters * bestLen; i < lines.Count; i++) result.Suffix.Add(lines[i]);
            result.Iterations = bestIters;
            return result;
        }

        /// <summary>
        /// Given a window [start, start+len), count how many times it repeats
        /// consecutively starting from `start`.
        /// </summary>
        private static int CountRepetitions(List<MethodTracer.TraceLine> lines, int start, int len)
        {
            int iters = 1;
            int pos = start + len;
            while (pos + len <= lines.Count && WindowsEqual(lines, start, pos, len))
            {
                iters++;
                pos += len;
            }
            return iters;
        }

        private static bool WindowsEqual(List<MethodTracer.TraceLine> lines, int a, int b, int len)
        {
            for (int i = 0; i < len; i++)
            {
                var x = lines[a + i];
                var y = lines[b + i];
                if (x.HandlerToken != y.HandlerToken) return false;
                if (x.Label != y.Label) return false;
            }
            return true;
        }
    }
}

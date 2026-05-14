using System.Collections.Generic;
using dnlib.DotNet;

namespace EazFixer {
    internal class Flags
    {
        public static string  InFile;
        public static string  OutFile;

        public static bool    KeepTypes;
        public static bool    VirtFix;
        public static bool    PreserveAll;
        public static bool    NoDevirt;
        public static bool    TraceOnly;
        public static bool    KeepVmTypes;

        public static MDToken StrDecTok;
        public static MDToken ResResolverTok;
        public static MDToken ResInitTok;
        public static MDToken AsmResTypeTok;
        public static MDToken AsmResMoveNextTok;
        public static MDToken AsmResDecompressTok;
        public static MDToken AsmResDecryptTok;

        /// <summary>
        /// Parsed patch specs: method MDToken -> desired return value descriptor.
        /// Populated from --patch flags in Program.handleOptions.
        /// </summary>
        public static readonly List<(uint Token, string ValueSpec)> PatchSpecs = new();

        public static bool DumpOpcodeMap;
        public static bool DeobCflow;
        public static bool CleanNames;
        public static bool DevirtRewrite;
        public static bool DevirtFoldLoops;
        public static bool NoDevirtFoldLoops;
        public static bool TraceAllVmStubs;
        public static readonly List<string> ProbeDependencyPaths = new();
        public static string VmProfile = "eaz2025-default";
        public static int TraceMaxIntReads = 250000;
        public static int TraceMaxMs = 15000;
        public static bool TraceStreamPositions;
        public static bool TraceIsolated = true;
        public static int TraceWorkerTimeoutMs = 30000;
        public static int MapPrimerTimeoutMs = 3000;
        public static int MapBuildTimeoutMs = 15000;
        public static bool MapBuildIsolated = true;
        public static bool WorkerBuildMap;
        public static string WorkerMapOut;
        public static bool WorkerTrace;
        public static string WorkerTraceOut;

        public static readonly List<uint> TraceMethodTokens = new();

        /// <summary>Optional per-token argument list. Keyed by the same token
        /// that's in TraceMethodTokens. Missing tokens trace with defaults.</summary>
        public static readonly Dictionary<uint, object[]> TraceMethodArgs = new();

        /// <summary>
        /// When set, auto-scans and patches license/telemetry methods.
        /// </summary>
        public static bool StripLicenseTelemetry;

        /// <summary>
        /// When set, runs Eazfuscator self-patching mode.
        /// </summary>
        public static bool PatchEazfuscator;

        /// <summary>
        /// Hardcoded patch table for --patch-eazfuscator mode.
        /// </summary>
        public static readonly List<(uint Token, string ValueSpec)> EazfuscatorPatches = new();

        /// <summary>
        /// When set, only reports license candidates without patching.
        /// </summary>
        public static bool AnalyzeLicense;
    }
}

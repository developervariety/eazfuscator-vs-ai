using System.Collections.Generic;
using CommandLine;

namespace EazFixer
{
    class Options
    {
        [Option("file",
            Default = false,
            Required = true)]
        public string InFile { get; set; }

        [Option("out")]
        public string OutFile { get; set; }

        [Option("keep-types", HelpText = "Don't cleanup/remove obfuscator types")]
        public bool KeepTypes { get; set; }

        [Option("virt-fix", HelpText = "Don't process obfuscated parts necessary for the code virtualization to work")]
        public bool VirtFix { get; set; }
        
        [Option("preserve-all", HelpText = "Preserve all metadata")]
        public bool PreserveAll { get; set; }
        
        [Option("str-decrypt-tok", Default = "0", HelpText = "Manually specify string decryptor method token for if detection fails (Format: 0x<token>) ")]
        public string StrDecTok { get; set; }
        
        [Option("res-resolver-tok", Default = "0", HelpText =  "Manually specify resource resolver type token for if detection fails (Format: 0x<token>) ")]
        public string ResResolverTok { get; set; }
        
        [Option("res-init-tok", Default = "0", HelpText =  "Manually specify resource init method token for if detection fails (Format: 0x<token>) ")]
        public string ResInitTok { get; set; }
        
        [Option("asmres-type-tok", Default = "0", HelpText = "Manually specify assembly decryptor type token for if detection fails (Format: 0x<token>) ")]
        public string AsmResTypeTok { get; set; }
        
        [Option("asmres-movenext-tok", Default = "0", HelpText = "Manually specify assembly decryptor MoveNext token for if detection fails (Format: 0x<token>) ")]
        public string AsmResMoveNextTok { get; set; }
        
        [Option("asmres-decompress-tok", Default = "0", HelpText = "Manually specify assembly decompressor method token for if detection fails (Format: 0x<token>) ")]
        public string AsmResDecompressTok { get; set; }
        
        [Option("asmres-decrypt-tok", Default = "0", HelpText = "Manually specify assembly decryptor method token for if detection fails (Format: 0x<token>) ")]
        public string AsmResDecryptTok { get; set; }

        [Option("no-devirt", HelpText = "Skip the VM devirtualization processor")]
        public bool NoDevirt { get; set; }

        [Option("trace-only",
            HelpText = "Skip normal fixer processors and only run trace/rewrite " +
                       "pipeline features (trace/map/devirt-rewrite/cflow).")]
        public bool TraceOnly { get; set; }

        [Option("keep-vm-types", HelpText = "Keep the Eazfuscator VM runtime types in the output even after devirt")]
        public bool KeepVmTypes { get; set; }

        [Option("patch", Separator = ';',
            HelpText = "Rewrite a method body to return a constant. Repeat the flag or " +
                       "semicolon-separate: --patch 0x06000531=true --patch 0x06000532=int:42. " +
                       "Value specs: true, false, void, null, int:<n>, long:<n>, string:<s>")]
        public IEnumerable<string> Patches { get; set; }

        [Option("dump-opcode-map",
            HelpText = "Load the input assembly into this process, trigger VM cctor, " +
                       "and dump the full opcode -> handler-MDToken map to a CSV sidecar. " +
                       "Runs code from the target — only use on trusted binaries.")]
        public bool DumpOpcodeMap { get; set; }

        [Option("trace-method",
            HelpText = "Virtualized method tokens to trace, semicolon-separated. " +
                       "Each entry is TOKEN or TOKEN:arg1,arg2,... " +
                       "Example: --trace-method \"0x06000531:3,7;0x06000532:10\" " +
                       "Args are parsed as int32 (decimal or 0xNN hex). " +
                       "Runs code from the target.")]
        public string TraceMethod { get; set; }

        [Option("probe-dependency-paths", Separator = ';',
            HelpText = "Additional dependency probing directories for in-process " +
                       "VM map/trace loading. Semicolon-separated absolute paths.")]
        public IEnumerable<string> ProbeDependencyPaths { get; set; }

        [Option("vm-profile",
            HelpText = "VM decoding profile. Use 'eaz2025-default' for current " +
                       "behavior or 'custom' to run with custom-profile hooks.",
            Default = "eaz2025-default")]
        public string VmProfile { get; set; }

        [Option("trace-all-vm-stubs",
            HelpText = "Auto-detect all virtualized stubs in the current module " +
                       "and trace them (using default args unless also provided " +
                       "through --trace-method). Useful with --devirt-rewrite to " +
                       "rebuild all detected VM methods in one pass.")]
        public bool TraceAllVmStubs { get; set; }

        [Option("trace-max-int-reads",
            HelpText = "Per-stub guard: maximum int-read events captured before " +
                       "tracing the stub is aborted. Default: 250000.",
            Default = 250000)]
        public int TraceMaxIntReads { get; set; }

        [Option("trace-max-ms",
            HelpText = "Per-stub guard: approximate max tracing time in milliseconds " +
                       "before aborting on opcode reader activity. Default: 15000.",
            Default = 15000)]
        public int TraceMaxMs { get; set; }

        [Option("trace-stream-positions",
            HelpText = "Experimental: capture sampled stream positions for opcode-reader " +
                       "events to aid static CFG reconstruction profiling.",
            Default = false)]
        public bool TraceStreamPositions { get; set; }

        [Option("map-primer-timeout-ms",
            HelpText = "Timeout in milliseconds for opcode-map primer invocation. " +
                       "Prevents map build stalls on hostile/custom stubs. Default: 3000.",
            Default = 3000)]
        public int MapPrimerTimeoutMs { get; set; }

        [Option("map-build-timeout-ms",
            HelpText = "Timeout in milliseconds for full opcode-map build call. " +
                       "If exceeded, map stage is aborted and tracing is skipped. Default: 15000.",
            Default = 15000)]
        public int MapBuildTimeoutMs { get; set; }

        [Option("map-build-isolated",
            HelpText = "Run opcode-map build inside a worker process for crash " +
                       "isolation. Recommended for custom/hostile VM targets.",
            Default = true)]
        public bool MapBuildIsolated { get; set; }

        [Option("worker-build-map",
            HelpText = "Internal mode: build opcode map and write portable output.")]
        public bool WorkerBuildMap { get; set; }

        [Option("worker-map-out",
            HelpText = "Internal mode output path for --worker-build-map.")]
        public string WorkerMapOut { get; set; }

        [Option("trace-isolated",
            HelpText = "Run map+trace in a separate worker process for crash " +
                       "isolation. Recommended for custom/hostile VM targets.",
            Default = true)]
        public bool TraceIsolated { get; set; }

        [Option("trace-worker-timeout-ms",
            HelpText = "Timeout in milliseconds for the trace worker process. " +
                       "Default: 30000.",
            Default = 30000)]
        public int TraceWorkerTimeoutMs { get; set; }

        [Option("worker-trace",
            HelpText = "Internal mode: build map and run traces, then write " +
                       "portable trace output.")]
        public bool WorkerTrace { get; set; }

        [Option("worker-trace-out",
            HelpText = "Internal mode output path for --worker-trace.")]
        public string WorkerTraceOut { get; set; }

        [Option("deob-cflow",
            HelpText = "Run a control-flow deobfuscator across all methods. " +
                       "Flattens Eazfuscator's ldc.i4/brtrue/pop constant-branch " +
                       "patterns, which removes a large amount of dead code.")]
        public bool DeobCflow { get; set; }

        [Option("clean-names",
            HelpText = "Rename unreadable obfuscated identifiers to stable ASCII names for dnSpy browsing.")]
        public bool CleanNames { get; set; }

        [Option("devirt-rewrite",
            HelpText = "After --trace-method or --trace-all-vm-stubs captures stubs, " +
                       "rewrite the stub's body with the traced CIL sequence. " +
                       "Branches in the trace become no-ops — this yields a " +
                       "straight-line representation of the specific execution " +
                       "path. Great for dnSpy readability, not runtime-equivalent.")]
        public bool DevirtRewrite { get; set; }

        [Option("devirt-fold-loops",
            HelpText = "With --devirt-rewrite, collapse repeated opcode runs " +
                       "into a deterministic counted loop that replays traced " +
                       "iterations. Produces much smaller, more decompiled-like " +
                       "method bodies while preserving traced behavior.")]
        public bool DevirtFoldLoops { get; set; }

        [Option("no-devirt-fold-loops",
            HelpText = "Disable loop folding during --devirt-rewrite and emit " +
                       "fully linear traces instead.")]
        public bool NoDevirtFoldLoops { get; set; }
    }
}

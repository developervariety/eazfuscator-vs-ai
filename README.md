# eazfuscator-vs-ai

Reverse-engineering and deobfuscation toolchain for assemblies protected by [Eazfuscator.NET](https://www.gapotchenko.com/eazfuscator.net). Includes `EazFixer` (the main CLI), `EazDevirt` (the VM devirtualizer library), and a set of analysis tools under `tools/`.

Tested against Eazfuscator.NET 2026.1 (build 2026.1.797.42414).

---

## Patching Eazfuscator Itself

If you own a copy of Eazfuscator.NET and want to enable enterprise features, suppress evaluation warnings, or remove time-bomb injection from protected output, you can patch the main DLL in-place.

### Prerequisites

- Eazfuscator.NET installed to its default path:
  `C:\Program Files (x86)\Gapotchenko\Eazfuscator.NET\`
- Built `EazFixer.exe` (see [Building](#building))
- An **elevated (Run as Administrator) PowerShell** for the final copy

### Step 1 — Build EazFixer

```powershell
dotnet build EazFixer\EazFixer.csproj -c Release
```

Output: `EazFixer\bin\Release\net481\EazFixer.exe`

### Step 2 — Patch to a temp file (no elevation needed)

```powershell
$dll     = "C:\Program Files (x86)\Gapotchenko\Eazfuscator.NET\Components\Gapotchenko.Eazfuscator.NET.dll"
$tmp     = "$env:TEMP\eaz-patched.dll"
$eazfixer = "EazFixer\bin\Release\net481\EazFixer.exe"

& $eazfixer --patch-eazfuscator --no-devirt --file $dll --out $tmp
```

Expected output (representative — heuristic count varies by build, all core patches applied):

```
[LicensePatcher] Running heuristic scan for license/eval patch targets...
    heuristic 0x06006775 -> void                 (VM warning callback void(bool) → no-op)
    heuristic 0x06007BE0 -> true                 (license compute bool(Nullable<int>, bool) → true)
    heuristic 0x060083E3 -> void                 (VM warning callback void(bool) → no-op)
    heuristic 0x06008697 -> int:7                (edition parser (codes {1,2,3,5},MaxValue) → 7)
    heuristic 0x0600887A -> true                 (license cache check (MemoryCache/ObjectCache) → true)
    heuristic 0x06008A01 -> int:7                (edition parser (codes {1,4,5,7},MaxValue) → 7)
    heuristic 0x06008E09 -> true                 (license cache check (MemoryCache/ObjectCache) → true)
    heuristic 0x0600941F -> bool-args-false      (eval state notifier (3 bool args packed) → all false)
    heuristic 0x06009430 -> bool-args-false      (context builder (3 bool args packed) → all false)
[LicensePatcher] Heuristic scan found 9 candidate(s).
[LicensePatcher] Built-in table supplemented 9 additional entry/ies.
  patched 0x06006775 -> void                  (VM warning callback)
  patched 0x06007BE0 -> true                  (license compute bool(Nullable<int>, bool))
  patched 0x060083E3 -> void                  (VM warning callback)
  patched 0x06008697 -> int:7                 (edition parser)
  patched 0x0600887A -> true                  (license cache check)
  patched 0x06008A01 -> int:7                 (edition parser)
  patched 0x06008E09 -> true                  (license cache check)
  patched 0x0600941F -> bool-args-false       (eval state notifier)
  patched 0x06009430 -> bool-args-false       (context builder)
  patched 0x06008E0A -> true                  (secondary license validator)
  patched 0x06007BDE -> int:7                 (edition int getter)
  patched 0x06007BDF -> int:7                 (edition int getter bool overload)
  patched 0x06006BA1 -> int:7                 (edition name parser)
  patched 0x06006BAE -> true                  (enterprise feature gate)
  patched 0x06009418 -> void                  (VM warning callback)
  patched 0x06001CC2 -> void                  (timer callback)
  patched 0x06001CBF -> void                  (timer starter)
  patched 0x06001CC0 -> void                  (timer starter)
```

The patcher runs a structural heuristic scan first (version-independent) then supplements with the built-in 2026.1 token table for any entries the heuristic missed. On a new Eazfuscator build, supply `--eazfuscator-patch-table` for the new tokens.

> **Important:** Always patch from the original, unmodified DLL. Patching an already-patched output produces unpredictable results. If you accidentally patched twice, repair your Eazfuscator installation first.

### Step 3 — Deploy (elevated PowerShell)

```powershell
Copy-Item "$env:TEMP\eaz-patched.dll" `
  "C:\Program Files (x86)\Gapotchenko\Eazfuscator.NET\Components\Gapotchenko.Eazfuscator.NET.dll" `
  -Force
```

### Step 4 — Bypass strong-name verification

The patched DLL has an invalid signature. Add this to
`C:\Program Files (x86)\Gapotchenko\Eazfuscator.NET\eazfuscator.net.exe.config`
inside the `<runtime>` element:

```xml
<bypassTrustedAppStrongNames enabled="true" />
```

### What the patches do

| Token | Spec | Effect |
|---|---|---|
| `0x06007BE0` | `true` | EvaluateOnce\<bool\> stream compute → always licensed |
| `0x06008E0A` | `true` | Secondary MemoryCache license validator → true |
| `0x06007BDE` | `int:7` | Edition int getter → max edition |
| `0x06007BDF` | `int:7` | Edition int getter (bool overload) → max edition |
| `0x06006BA1` | `int:7` | Edition name string parser → max edition |
| `0x06006BAE` | `true` | Per-assembly enterprise feature gate → always enabled |
| `0x0600941F` | `bool-args-false` | Eval state notifier: force isEvaluation/isWatermarked → false |
| `0x06009418` | `void` | VM warning callback → no-op |
| `0x06009430` | `bool-args-false` | Obfuscation context builder: force eval bools → false |
| `0x06001CC2` | `void` | 1-second timer callback → no-op (suppresses EF-4008) |
| `0x06001CBF` | `void` | Timer starter → no-op |
| `0x06001CC0` | `void` | Timer starter → no-op |

On a different Eazfuscator build, the heuristic scan will still find structurally stable patches (bool-args-false, MemoryCache checks, the Nullable\<int\>/bool license compute signature). For anything the heuristic misses, use `--analyze-license` to locate new tokens and supply them with `--eazfuscator-patch-table`.

---

## Deobfuscating a Protected Assembly

`EazFixer` runs a pipeline of processors on a target assembly protected by Eazfuscator.NET.

### Minimal usage

```powershell
EazFixer.exe --file MyApp.exe --out MyApp.clean.exe --no-devirt
```

### Full deobfuscation with VM devirtualization

```powershell
EazFixer.exe --file MyApp.exe --out MyApp.clean.exe `
    --trace-all-vm-stubs --devirt-rewrite --deob-cflow --clean-names
```

---

## All Flags

### Core I/O

| Flag | Description |
|---|---|
| `--file <path>` | **(Required)** Input assembly to process. |
| `--out <path>` | Output path. Defaults to `<input>-eazfix<ext>`. |

### Deobfuscation processors

| Flag | Description |
|---|---|
| `--no-devirt` | Skip the VM devirtualization processor entirely. Use when you only need string/resource fixes or patching. |
| `--keep-types` | Do not remove Eazfuscator's injected runtime types from the output. |
| `--virt-fix` | Preserve obfuscated code that is required for the VM to function (for partial deobfuscation). |
| `--keep-vm-types` | Keep the Eazfuscator VM runtime types even after devirtualization. |
| `--deob-cflow` | Flatten the `ldc.i4 / brtrue / pop` constant-branch pattern Eazfuscator injects. Removes large amounts of dead code. Combine with `--devirt-rewrite` for best results. |
| `--clean-names` | Rename unreadable obfuscated identifiers to stable ASCII names for dnSpy browsing. Disables `--preserve-all` automatically if names are changed. |
| `--preserve-all` | Force preservation of all metadata token values in the output. Required when downstream tools reference tokens by RID. Implied automatically by `--patch-eazfuscator`. |

### Manual token overrides

Use these when auto-detection fails on a non-standard build:

| Flag | Description |
|---|---|
| `--str-decrypt-tok <0xToken>` | String decryptor method token. |
| `--res-resolver-tok <0xToken>` | Resource resolver type token. |
| `--res-init-tok <0xToken>` | Resource initializer method token. |
| `--asmres-type-tok <0xToken>` | Assembly decryptor type token. |
| `--asmres-movenext-tok <0xToken>` | Assembly decryptor `MoveNext` token. |
| `--asmres-decompress-tok <0xToken>` | Assembly decompressor method token. |
| `--asmres-decrypt-tok <0xToken>` | Assembly decryptor method token. |

### VM tracing and devirtualization

These options run code from the target assembly in-process or in a worker. Only use on trusted binaries.

| Flag | Description |
|---|---|
| `--trace-method <spec>` | Virtualized method tokens to trace. Semicolon-separated. Each entry is `TOKEN` or `TOKEN:arg1,arg2,...`. Example: `--trace-method "0x06000531:3,7;0x06000532"` |
| `--trace-all-vm-stubs` | Auto-detect all virtualized stubs and trace them. Combine with `--devirt-rewrite`. |
| `--devirt-rewrite` | After tracing, rewrite each stub's body with the traced CIL sequence. Produces dnSpy-readable output; not runtime-equivalent. |
| `--devirt-fold-loops` | During `--devirt-rewrite`, collapse repeated opcode runs into counted loops (smaller, more readable output). |
| `--no-devirt-fold-loops` | Force fully linear (unrolled) trace output during `--devirt-rewrite`. |
| `--trace-max-int-reads <n>` | Per-stub guard: abort tracing after N int-read events. Default: `250000`. |
| `--trace-max-ms <ms>` | Per-stub guard: abort tracing after ~N milliseconds. Default: `15000`. |
| `--trace-isolated` | Run map+trace in a separate worker process for crash isolation. Default: `true`. |
| `--trace-worker-timeout-ms <ms>` | Timeout for the trace worker process. Default: `30000`. |
| `--map-build-isolated` | Run opcode-map build in a worker process. Default: `true`. |
| `--map-primer-timeout-ms <ms>` | Timeout for the opcode-map primer. Default: `3000`. |
| `--map-build-timeout-ms <ms>` | Timeout for the full opcode-map build. Default: `15000`. |
| `--dump-opcode-map` | Dump the full VM opcode→handler-token map to a `.csv` sidecar next to the output file. |
| `--vm-profile <name>` | VM decoding profile. Use `eaz2025-default` (default) or `eaz2026-default`. |
| `--probe-dependency-paths <paths>` | Semicolon-separated extra directories for loading the target's dependencies. |
| `--trace-only` | Skip all standard processors; only run the trace/map/rewrite pipeline. |

### Return patching

Rewrite any method body to unconditionally return a constant — useful for disabling feature gates or neutralising activation stubs.

| Flag | Description |
|---|---|
| `--patch <token>=<spec>` | Patch one method. Repeat or semicolon-separate for multiple. `<spec>` values: `true`, `false`, `void`, `null`, `int:<n>`, `long:<n>`, `string:<text>`, `bool-args-false`. Example: `--patch 0x06000531=true --patch 0x06000532=int:42` |

`bool-args-false` is a special in-place spec: instead of replacing the whole body, it finds every `ldarg.X; box System.Boolean` pair and replaces the load with `ldc.i4.0`, forcing all boxed boolean arguments to false. Used for methods that forward boolean state into a VM stream.

### License patching

| Flag | Description |
|---|---|
| `--patch-eazfuscator` | Patch `Gapotchenko.Eazfuscator.NET.dll` itself using the built-in token table. Use `--no-devirt` to skip devirtualization of the Eazfuscator binary. Automatically preserves all metadata RIDs on write. |
| `--eazfuscator-patch-table <entries>` | Semicolon-separated `token=spec` overrides for `--patch-eazfuscator`. Replaces the built-in table when supplied. Example: `--eazfuscator-patch-table "0x06000001=true;0x06000002=int:7"` |
| `--analyze-license` | Scan the input assembly for license/telemetry/trial-expiry/feature-gate methods and print candidate tokens with suggested specs — without patching anything. Use this to discover tokens for `--patch` or `--eazfuscator-patch-table` on unknown builds. |
| `--strip-license-telemetry` | Auto-detect and patch license, trial-expiry, telemetry, and feature-gate methods in the target assembly (not Eazfuscator itself). Heuristic-based; combine with `--analyze-license` output to tune. |

---

## Building

Requires .NET SDK 8+ and .NET Framework 4.8.1 targeting pack.

```powershell
# EazFixer (net481 for deployment, net10.0 also built)
dotnet build EazFixer\EazFixer.csproj -c Release

# EazDevirt (library used by EazFixer)
dotnet build EazDevirt\EazDevirt.csproj -c Release
```

---

## Repository layout

```
EazFixer/          Main CLI and processors
  Processors/
    LicensePatcher.cs   Eazfuscator self-patch + license/telemetry strip
  ReturnPatcher.cs      Method body constant-return rewriter
  Options.cs            All CLI flags
EazDevirt/         VM devirtualizer library
docs/              Reverse-engineering notes and findings
```

# Eagle

## Soda build symbols

Fresh CI builds package Wine debug companions in a separate
`<component>-symbols.tar.xz` archive. The normal runner keeps debug links and
`share/soda/symbols.json`, which records image hashes, companion hashes and
debug-link CRCs. Core Wine launcher, server and ntdll DWARF companions are required.
Symbol-only companions and unavailable optional images are recorded separately.
Matching PDBs beside an image or in its `.debug` directory move into the symbol
archive after CodeView GUID/age checks. Shared PDBs are stored once. Missing
optional PDBs stay marked unavailable; identity-only PDB coverage does not satisfy
the required DWARF gate. The verifier checks PDB hashes and identities again.
The `--objcopy` option supports LLVM for PE files carrying DWARF and CodeView.
ELF split-DWARF builds retain matching units in `<debug-image>.dwp` beside the
separate debug image. The builder searches the runner and explicit `--debug-root`
directories; encoded build paths do not authorize reads outside those roots.
It checks unit IDs and hashes, rejects missing or ambiguous inputs, and records
the DWP hash and input hashes. External build files stay in place. Matching
companions inside the runner move into the optional archive.
This path requires existing host `readelf`, `llvm-dwarfdump` and, when packing
DWO files, `llvm-dwp`. Ordinary ELF DWARF does not require LLVM. Builder inspection
allows up to 65536 units and 64 MiB per tool response; interactive inspection
keeps its smaller limits. The verifier checks required IDs against the actual
debug image and retained DWP, including after archive relocation.

Use the archive for the exact runner component. Its directory layout overlays
the runner and includes the same source/build inventories. Extract it into the
runner's parent directory before resolving captured addresses. The build helper
`.github/soda-symbols.py RUNNER SYMBOLS --tools TOOLS --verify` checks the bundle
against its runner before packaging. Recovered older prebuilt runners may lack
symbols that were already discarded. Symbol archives do not certify target
architecture execution or complete source/type/inline coverage.

ELF address queries first use host binutils. For available source locations,
Eagle also checks host `llvm-symbolizer`. Matching DWARF names can complete a
missing name or replace a nearby ELF symbol selected by binutils. This covers
split packages without ordinary ELF symbol names. A replacement requires both
resolvers to agree on the source file and line. Missing or failed LLVM tools
preserve the GNU result; incomplete or failed lookups include `symbol_reason`.
Unresolved addresses do not start another resolver.

Inspect source checksum records or check files selected for review:

```sh
eagle symbols module --sources
eagle symbols module --source-file /reviewed/fixture.c
```

The stdio `symbols` method accepts `sources: true` and a `source_files` list.
Only explicit files are opened; encoded source paths are listed without reads.
Clang DWARF5 can record MD5 checksums. A missing checksum remains `not-recorded`,
including ordinary GCC and DWARF4 fixtures. Selected files report `matched`,
`mismatched`, `not-recorded`, `not-referenced`, `missing` or `invalid`, with SHA256
of observed content and indexes of matching DWARF entries. MD5 association does
not certify source authenticity, DWO types or inline data.
Separate GNU debug images require a matching CRC. Inspection streams address
rows without retaining them, allows 4096 file entries and 256 explicit files,
and uses a shared 20-second budget. Tool output is bounded at 256 MiB streamed,
1 MiB of retained headers and a 512 KiB source report. Limits and missing tools
are reported as unavailable. Default identity queries remain unchanged.

Check a reviewed file against the recorded Soda build inputs, including when
DWARF does not carry a checksum:

```sh
eagle symbols /runner/bin/wine --runner-root /runner \
    --source-map wine:dlls/ntdll/unix/process.c=/reviewed/process.c
```

The stdio method accepts `runner_root` and `source_maps`, a list of objects with
`source`, `path` and `file` fields. `source` selects the recorded source label,
`path` is its exact relative inventory key and `file` is the explicit file to hash.
The report verifies the queried image, both inventory digests and reconstructed
source tree identities. Recorded links resolve within that inventory, without
filesystem searches. External/cyclic links, partial metadata and changed inputs
are rejected. Old runners without recorded sources remain unavailable.
`build_sources.status: available` describes the inventory chain; each file has
its own matched/mismatched/missing/not-recorded/invalid status. This records build
input membership, not per-module compiler use or authenticity. DWARF checksum
results remain separate. Inventories are limited to 32 MiB each, mappings to 256
and inspection to a shared 20-second budget with a 512 KiB report limit.
Combined source-query responses are limited to 768 KiB before CLI/backend output.

Soda 11.0-26 Experimental includes the debugger and tracing commands on Linux
x86_64. It supports x86 and x64 targets. Bottles keeps its existing analyzer.
The native analyzer replacement is still in development and is not included
in this release.

## Bottle tracing

The command below works with the released runner. The Bottles integration is
still in development. When that integration is available, enable **Eagle Tracing** in the bottle's
Performance settings. Reproduce the problem once, close the application, then
turn tracing off. **Open Trace Logs** opens `logs/runs` inside the bottle.
Each launch writes a separate `.log` after its process tree exits.
Relative program names are resolved in the requested working directory before
the bottle's system32 directory, including an implicit `.exe` suffix and
case-insensitive Windows path components. Explicit Unix paths stay exact.
While the application is open, a `.running.log` is readable in the same folder.
If the application hangs, this file can be reviewed and shared before closing
it. It uses JSON lines, is marked incomplete and stops at a 16 MiB limit.
The final `.log` replaces it after collection ends and includes recent process
and exception history. Capture errors retain a partial report.

Read the log before uploading it. Paths and arguments are redacted, but
application identifiers, class names and other trace text can contain private
information. Share the `.log`, runner version and reproduction steps.
The adjacent `.session` directory contains raw events and can contain dumps;
it is private diagnostic data, not the upload file.
Exports are written to a private temporary file in the destination directory,
flushed, then linked to the final name without replacing existing files.
Write or flush failures leave no partial final file; tracing retains its live
log and raw bundle. The destination filesystem must support hard links.

Tracing adds debugger and observer overhead. It does not fix application
compatibility. The tested target architectures are x86 and x64. Mixed
architecture process trees and ARM runner execution are not yet certified.
Each capture shares at most 1024 file identities across child inventories and
module loads. File device, inode, size, modification and change times must match;
changed files are rehashed. Process mappings remain separate, and the cache
is discarded after the capture.
Console input/output is disconnected during collection.
Passive tracing excludes Wine's builtin console host in the Windows system
directory and records that exclusion. Application children are still traced;
an application named `conhost.exe` is not excluded by its name alone.

## Command line

Automatic collection, with one reviewed log per launch:

```sh
/path/to/runner/bin/eagle trace \
    --wine /path/to/runner/bin/wine \
    --prefix /path/to/bottle \
    --logs /path/to/bottle/logs/runs \
    --cwd /path/to/application -- /path/to/application/app.exe
```

For an interactive session, use a new, short session path:

```sh
/path/to/runner/bin/eagle run \
    --wine /path/to/runner/bin/wine --prefix /path/to/bottle \
    --session /path/to/session --profile debug --interactive \
    /path/to/application/app.exe
```

Profiles `winrt`, `dwrite`, `com` and `wait` enable the corresponding Wine
observers; `trace` enables all four. HRESULT triggers are available with
`winrt`, `dwrite` and `com`, for example
`--on-hresult 0x80040154 --trigger-action snapshot`.

The COM observer covers activation, requested apartments and activation-time
interface queries. The wait graph covers observed KernelBase mutex handles
within each process. A cycle is evidence of an observed wait relationship,
not proof of a permanent deadlock. Missing symbols stay marked unavailable.
Caller frames can report function and source line when matching symbols exist.

## Session comparison

`eagle compare BASELINE CANDIDATE` compares recorded event counts. Snapshot
fingerprints retain the ordered `(module, RVA)` stack, unwind method and
truncation flag. Caller, order, depth and recorded unwind changes are visible.
RVAs use canonical hexadecimal values, including integer inputs. Absolute
addresses, registers, process/thread IDs, times and resolved source/symbol
names do not create differences. Existing provider payload comparisons remain.

Session readers validate single frames and frame arrays before inspect,
compare or export. Malformed stacks and RVAs return a structured error;
exports are not created. Partial frames and empty stacks remain readable.
The reader accepts up to 4096 frames per event; native snapshots capture up
to 128. Missing stack data differs from an explicitly recorded empty stack.
Unknown frames remain unknown. Matching fingerprints do not prove identical
execution or matching module contents; compare inputs and module identities.

## Saved-session symbols

`inspect` and `export` accept `--symbol-images reviewed.json`. The file is a
JSON list of explicitly reviewed image selections:

```json
[{"sha256":"<64-character recorded SHA256>","image":"/reviewed/module.dll","pdb":"/reviewed/module.pdb"}]
```

The stdio methods accept the same list as `symbol_images`. `pdb` and
`debug_files` (DWO/DWP paths) are optional; `inlines` defaults to true.
Selections accept up to 256 images and a 1 MiB JSON file. Empty debug-file
lists select no explicit companions. Default inspect/export output is unchanged.

Enrichment uses recorded per-load identities with exact image paths, process
IDs and load bases. Unload, exit and PID reuse remove old associations; an
ambiguous load or missing identity stays unavailable. Sessions without load
history can use exact manifest paths, marked `runtime unverified`. Paths
encoded in a session are never opened. Only selected image paths are read,
and their SHA-256 and file state must match before/after symbol lookup.

Original capture fields remain present. `offline_symbols` adds separate
source/inline results; `offline_symbolization` reports selected artifact
identities and counts. At most 256 unique addresses are queried, with terminal
exceptions first, then recent snapshots, then other frames. Duplicates reuse
results. Other frames retain an explicit unavailable reason. Existing bounded
symbol queries run under an overall deadline checked between operations.

Exports remove selected paths, source paths and `offline_diagnostic` details,
keep mode 0600 and still require review. Image hashes match recorded files;
they do not certify that a prefix-file fallback was the actual runtime image.

## Exported and live log inputs

`inspect` and `export` accept a full session directory, a finalized `.log`
summary or an `eagle-live-v1` `.running.log`. The stdio methods use the same
`session` parameter. Imported report files must be regular files, at most
32 MiB. Full-bundle behavior is unchanged.

Finalized summaries preserve their declared counts and omission metadata.
Retained records are ordered by collector sequence numbers; identical events
shown in several views share one record. Conflicting sequence data is invalid.
When sequence information is missing, inspection still works, but reviewed
symbol enrichment marks the frame order unavailable. Missing load history
stays unavailable. Redacted image aliases require recorded address/base data.

Live logs retain file order and remain partial even after a `finished` event.
An incomplete final JSONL line is marked and ignored; malformed complete or
middle records fail. Capture-limit/error markers remain visible. Imported
memory events and raw dump bodies are excluded; dump metadata remains.

`input_coverage` states the retained history and ordering limits. Optional
`--symbol-images` enrichment uses that retained evidence without reopening
recorded paths. Re-export keeps path/diagnostic redaction, mode 0600 and review.
Run comparison requires complete session directories: exported views cannot
establish matching run inputs or recover omitted events.

## Backend messages

`eagle serve` uses Content-Length frames with a 1 MiB body limit. Request IDs
are strings or integers of at most 1024 bytes after JSON encoding; synchronous
requests may also use null. Invalid IDs receive `-32600` with a null ID before
dispatch, and valid following requests still work. The initialize response
advertises these limits under `stdio`.

Oversized results receive `-32603` without a partial or truncated result. Large
error details receive a bounded diagnostic with the original error code. An
oversized output event fails its capture job and closes the collector; data
already written to the session remain available. Reports beyond the stdio limit
can be read with CLI commands or file export. Invalid input framing receives
`-32700` and ends that stream; no frame resynchronization is attempted.
CLI output and the DAP adapter keep their existing transport behavior.

## Offline symbols (development)

Look up function names and source lines by RVA without launching the target:

```sh
eagle symbols ./module --rva 0x1120 --rva 0x1140
```

The stdio `symbols` method accepts `path`, optional `pdb` and an optional `rvas`
array of integer addresses or numeric strings. Queries accept up to 256 RVAs
inside the image. Each result reports `source-resolved`, `symbol-only` or
`unresolved`; a missing resolver returns an error. Omitting RVAs keeps the
existing identity response.

DWARF/symbol-table lookup uses host binutils for ELF and x86/x64 PE images.
ARM64 PE DWARF queries use host `llvm-symbolizer`, including matching GNU
debug-link companions. Missing tools remain an explicit lookup failure.
With `--pdb ./module.pdb`, source
lookup uses a host `llvm-symbolizer` (including version-suffixed executables).
The selected PDB must match the PE GUID and age. Temporary links select that
file even when it was moved or another PDB sits beside the image; the files
are not copied or modified. Omitting RVAs still checks identity without LLVM.
Source lines available in split-DWARF skeletons do not establish that the
complete companion debug information is available.

The offline PDB fixture tests require `clang-cl`, `lld-link` and
`llvm-symbolizer`. They report a skip if these optional host tools are absent;
`EAGLE_TEST_LLD_LINK` can select a linker executable for the tests.

Include compiler inline contexts with `--inlines` (stdio `inlines: true`):

```sh
eagle symbols ./module --rva 0x1120 --inlines
```

This requires host `llvm-symbolizer` and requested RVAs. The original result
stays present; `inline_frames` adds up to 64 contexts, innermost first, with
function, file, line, column and an `inlined` flag. `inline_status` distinguishes
`available` chains, a single `not-reported` context, `unresolved` addresses and
`unavailable` lookups with an explicit reason. A single context does not prove
that the function has no inlines. Matching PDB selection and GNU debug-link CRC
checks apply. Symbolizer output is limited to 16 MiB and 10 seconds.

Owned optimized fixtures cover GCC/Clang DWARF 4/5 ELF, x86/x64 PE DWARF and
x86/x64/ARM64 PDBs. These are static symbol lookups, not target execution.
Legacy GNU `.zdebug_*` ELF sections are normalized in a temporary image for
inline lookup. The native ELF helper checks compression headers and declared
sizes; Python zlib expands the sections in bounded chunks, then an existing
host `llvm-objcopy` or `objcopy` replaces and renames them. Original image
identity fields must match after conversion. `inline_debug_image` records
the original path/SHA-256 and normalized SHA-256. GNU debug-link CRC selection
happens first; originals are unchanged and temporaries removed on all exits.
Input and expanded debug data are each limited to 256 MiB; output is limited
to 512 MiB. Standard `SHF_COMPRESSED` zlib needs no conversion. Static owned
fixtures cover ELF32/ELF64 and ARM64, detached symbols and selected DWO/DWP
inputs. Compressed DWO/DWP inputs themselves are not qualified by this path.

The local LLVM DWP 21 tool still times out packing the optimized GCC DWARF 5 fixture. Relocated split
chains are verified with GCC DWARF 4 and Clang DWARF 5 instead. DWO/DWP identity
inspection remains separate; inline lookup does not certify complete types,
all split companions or mixed CodeView/DWARF precedence.

For split ELF images, combine `--inlines` with `--debug-file reviewed.dwp` to
select a relocated package explicitly. The stdio equivalent is `debug_files`.
The selected DWP must contain every skeleton DWO identity; a partial package,
different matching contents or changed file makes inline lookup unavailable.
Identical copies are allowed. Explicit choices take precedence over adjacent
packages. Without explicit choices, existing `<debug-image>.dwp` and
`<image>.dwp` candidates receive the same checks. This requires host
`llvm-dwarfdump`; the package path, SHA-256 and requested unit IDs appear in
`inline_artifacts` only after successful lookup with that exact DWP.

Explicit DWO files also work with `--inlines --debug-file`. If no complete
DWP is selected, Eagle requires a matching DWO for every skeleton unit and
uses host `llvm-dwp` to assemble a temporary package. It verifies the new CU
index before lookup, checks the original inputs after lookup and removes the
package on success or failure. Identical copies are deduplicated; different
contents for the same unit are ambiguous. `inline_artifacts.inputs` records
the selected original paths and SHA-256 values, plus the assembled package
SHA-256. Temporary paths are omitted. Input and generated package sizes are
limited to 256 MiB; assembly uses the same 10-second tool/output budget.
The existing LLVM21 optimized GCC DWARF5 packing limit still applies.

Without selected DWO files or a selected/adjacent DWP, LLVM can still use its
own DWO discovery; no `inline_artifacts` verification is claimed for that path.
DWO/DWP unit identities do not certify source content, complete type
information or symbol authenticity.

Inspect split-DWARF companion identities separately from address lookup:

```sh
eagle symbols ./module --artifacts --debug-file ./symbols/module.dwp
```

Inspection follows a separate GNU debug image only after its debug-link CRC
matches. The report includes that file's SHA-256 and checks DWO/DWP identities
against its skeleton units. It also searches for `<debug-image>.dwp` beside the
separate debug file. Missing or changed debug images remain unavailable.

The stdio method accepts `artifacts: true` and optional `debug_files` paths.
The report compares skeleton DWO IDs with DWO units or DWP CU indexes and
includes companion SHA256 values. Missing, mismatched and invalid candidates
remain distinct. Matching IDs do not certify full types, inline data or source
content; skeleton source lines can remain available without a companion.
Inspection requires host `llvm-dwarfdump`, accepts up to 256 units/files and
uses a shared 20-second budget with a 1 MiB limit on each tool response.
Tool absence or an inspection limit is reported as unavailable. Default
identity and source queries are unchanged unless artifact inspection is requested.
References come from the inspected image's debug information. A skeleton stored
in a separate debug file must be inspected through that file.

Split-DWARF fixture tests require GCC and LLVM's dumper/packager tools. Set
`EAGLE_TEST_DWARFDUMP` and `EAGLE_TEST_DWP` for version-suffixed executables;
the tests report a skip when the tools are absent.

## Build identities

Package builds write `share/eagle/build.json` with the Eagle source revision,
dirty state, source-file hashes, compiler versions, packaged-file hashes and
native symbol identities. Source archives without Git metadata retain a source
tree hash and report no revision. The manifest describes Eagle package assembly;
it does not attest the full Wine build or every upstream source.

Each capture records the Wine launcher and collector SHA256 values plus the
manifest digest and source identity. A collector mismatch is explicit. Older
packages without build metadata remain usable and report that it is unavailable.
Capture checks the collector digest rather than hashing the entire installed
runner on every launch. A process-creation failure preserves the manifest and
empty event history for inspection/export and closes its control socket.

Soda builds also write `share/soda/build.json`, `files.json` and `sources.json`.
The summary ties the launcher and file index to the supplied source revisions,
source-tree hashes, patch-file inventory and configuration hashes. Binary entries
retain ELF build IDs and PE CodeView identities through the native parsers.
Symlink targets are recorded without being followed. Patch inventory does not
attest application order or replace a snapshot of the patched Wine tree.

The workflow saves compilation provenance before pre-test upload, then refreshes
the file index after Eagle is installed. Refresh preserves compilation sources
and records the packaging source separately. Old recovered artifacts without
source metadata report it as unavailable. Captures include `runner_build` with
the observed launcher digest and recorded source identities; full inventories
are not rehashed on each launch.

## Build and verification

`.github/build-eagle.sh RUNNER WORK` builds and installs the debugger/tracing
package into an existing Wine runner and tests observer-off/on behavior for
WinRT, DirectWrite, COM and mutex waits on x86 and x64. `WORK` must be a new
persistent build directory. `build-debugger.sh DESTINATION` builds the package
separately.

`sh build-analysis.sh DESTINATION` builds and tests the native analysis and
Intel helpers and the developing native driver, using static json-c, GLib
and SQLite libraries. The driver reads one JSON request on standard input
and emits JSON lines for progress followed by the report. PE, directory,
neighbor, ASAR and installer analysis are under comparison with the existing
backend. Installer extraction uses an available 7z, 7za or 7zr command, with
the existing optional patool module as an external fallback. A caller can
pass its Python executable through `extractor_python` for that fallback.
SIGINT and SIGTERM stop the active helper group and return a cancelled result.
Helper timeouts and normal completion also stop and reap descendants in that
group. Extraction workspaces are removed on these paths. Processes that leave
the helper group, SIGKILL and uninterruptible filesystem operations are outside
these cleanup guarantees. Complete runtime packaging remains open.
The driver requires the native rule scanner and its data alongside these helpers.
When the driver, helpers, configuration, rules and Intel database are present,
`eagle analyze` and the stdio `analyze` method use the native driver. The Python
adapter forwards progress, returns the report and sends interruption requests
to the driver on cancellation. Incomplete packages do not advertise analysis.
This adapter does not certify full feature parity or enable the analyzer in
the debugger-only runner package.

`sh build-native.sh DESTINATION YARA_SOURCE WORK` builds an optional development
package containing the debugger and native analyzer. `YARA_SOURCE` must be a
local checkout at the revision in `sources.json`; `DESTINATION` and `WORK` must
not exist, and `WORK` must be outside `DESTINATION`. The build exports that
revision into its own tree, builds a static
scanner with two jobs by default, checks the bundled data hashes and includes
the database notices and scanner license. It neither downloads dependencies
nor installs libraries on the host. The package contains no Python analysis
engine. Full parity, ARM and portability checks remain separate requirements.

Manifest inspection reads XML elements and attribute values. DPI recommendations
use the recognized `dpiAware` values and the ordered `dpiAwareness` modes, with
the latter taking precedence as on Windows 10 versions that support it. Qualified
settings must use their Microsoft namespace, including inherited and locally
rebound prefixes. Unqualified fragments remain accepted for existing callers.
This does not emulate earlier Windows manifest behavior or validate the full
manifest schema. See the [Microsoft manifest reference](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests).

Runtime dependency suggestions use a stable order by label.

Unreal shipping suggestions ignore matching directories and broken links.
Links to regular files remain accepted.

The PE helper exposes ordered `version_tables` alongside the flattened
`version` dictionary. Product and publisher selection uses the last nonempty
value across those tables, matching the existing Bottles analyzer.

The debugger regression suite is `tests/integration.py`. Session/export
controls are in `tests/test_session_contract.py`; automatic per-launch logging
is in `tests/test_tracing.py`. Their environment variables select an immutable
candidate, private Wine prefix and test directory.

The diagnostic release keeps the published Soda 25 runtime and replaces
`combase`, `dwrite` and `kernelbase` for both target architectures. Build those
DLLs from the pinned Wine source with the Soda patches and
`zzz-eagle-debug-providers.mypatch` applied. Use
`-ffile-prefix-map=BUILD_ROOT=/usr/src/soda` for the provider DLLs and their
static Wine libraries to keep local build paths out of the symbols.
`.github/package-eagle-overlay.sh BASELINE_ARCHIVE WINE_BUILD WORK` verifies
the published baseline checksum, installs the DLLs, builds Eagle, runs the
acceptance tests and creates the runner archive.

# Eagle

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

Tracing adds debugger and observer overhead. It does not fix application
compatibility. The tested target architectures are x86 and x64. Mixed
architecture process trees and ARM runner execution are not yet certified.
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

DWARF/symbol-table lookup uses host binutils. With `--pdb ./module.pdb`, source
lookup uses a host `llvm-symbolizer` (including version-suffixed executables).
The selected PDB must match the PE GUID and age. Temporary links select that
file even when it was moved or another PDB sits beside the image; the files
are not copied or modified. Omitting RVAs still checks identity without LLVM.
Source lines available in split-DWARF skeletons do not establish that the
complete companion debug information is available.

The offline PDB fixture tests require `clang-cl`, `lld-link` and
`llvm-symbolizer`. They report a skip if these optional host tools are absent;
`EAGLE_TEST_LLD_LINK` can select a linker executable for the tests.

Inspect split-DWARF companion identities separately from address lookup:

```sh
eagle symbols ./module --artifacts --debug-file ./symbols/module.dwp
```

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

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

## Build and verification

`.github/build-eagle.sh RUNNER WORK` builds and installs the debugger/tracing
package into an existing Wine runner and tests observer-off/on behavior for
WinRT, DirectWrite, COM and mutex waits on x86 and x64. `WORK` must be a new
persistent build directory. `build-debugger.sh DESTINATION` builds the package
separately.

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

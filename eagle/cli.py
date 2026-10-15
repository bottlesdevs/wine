import argparse
import json
import sys
import subprocess
import signal
from pathlib import Path

from session import capture, compare, export, send_command, summary
from errors import Cancelled

def main():
    parser = argparse.ArgumentParser(prog="eagle")
    commands = parser.add_subparsers(dest="command", required=True)
    native = Path(__file__).resolve().parent / 'native'
    from analysis import available
    if available():
        analysis = commands.add_parser("analyze")
        analysis.add_argument("target")
        analysis.add_argument("--scan-limit", type=int, default=50)
        analysis.add_argument("--progress", action="store_true")
    if (native / 'eagle-yara').is_file():
        security = commands.add_parser('security-scan')
        security.add_argument('target')
    tracing = commands.add_parser('trace')
    tracing.add_argument('--wine', required=True)
    tracing.add_argument('--prefix', required=True)
    tracing.add_argument('--logs', required=True)
    tracing.add_argument('--cwd')
    tracing.add_argument('arguments', nargs=argparse.REMAINDER)
    for name in ("run", "attach"):
        run = commands.add_parser(name)
        run.add_argument("--wine", required=True)
        run.add_argument("--prefix", required=True)
        run.add_argument("--session", required=True)
        run.add_argument("--timeout", type=float, default=120)
        run.add_argument("--interactive", action="store_true")
        run.add_argument("--profile", choices=["crash", "process", "debug", "winrt", "dwrite", "com", "wait"], default="crash")
        run.add_argument("--break", dest="breakpoint")
        run.add_argument('--on-hresult')
        run.add_argument('--trigger-action', choices=['snapshot', 'dump', 'stop'], default='snapshot')
        if name == "run":
            run.add_argument("target")
            run.add_argument("arguments", nargs=argparse.REMAINDER)
        else:
            run.add_argument("pid", type=int)
            run.add_argument("--arch", choices=["x86", "x86_64"], default="x86_64")
    for name in ("inspect", "symbols"):
        item = commands.add_parser(name)
        item.add_argument("path")
        if name == "symbols":
            item.add_argument("--pdb")
            item.add_argument("--rva", action="append", help="resolve an RVA with host binutils; repeat for multiple addresses")
            item.add_argument("--artifacts", action="store_true", help="inspect split-DWARF companion identities")
            item.add_argument("--debug-file", action="append", help="inspect an explicit DWO or DWP companion")
            item.add_argument('--sources', action='store_true', help='inspect DWARF source file checksums')
            item.add_argument('--source-file', action='append', help='check an explicitly selected source file')
            item.add_argument('--runner-root', help='verify recorded Soda build inventories')
            item.add_argument('--source-map', action='append', help='check a recorded LABEL:RELATIVE=FILE source mapping')
    comparison = commands.add_parser("compare")
    comparison.add_argument("baseline"); comparison.add_argument("candidate")
    report = commands.add_parser("export")
    report.add_argument("session"); report.add_argument("output")
    control = commands.add_parser("control")
    control.add_argument("session"); control.add_argument("action", nargs="+")
    commands.add_parser("capabilities")
    commands.add_parser("serve")
    commands.add_parser("dap")
    args = parser.parse_args()
    try:
        if args.command == 'trace':
            from tracing import trace
            arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
            result = trace(args.wine, args.prefix, args.logs, arguments, args.cwd)
            print(json.dumps({'status': True, 'data': result}, indent=2))
            sys.exit(result['exit_code'] & 255)
        elif args.command == 'security-scan':
            from analysis import scan
            result = scan(args.target)
        elif args.command == "analyze":
            from analysis import analyze
            progress = (lambda text: print(json.dumps({"event": "step", "data": text}), flush=True)) if args.progress else None
            def interrupt(signum, frame):
                raise Cancelled('analysis cancelled')
            handlers = {value: signal.signal(value, interrupt) for value in (signal.SIGINT, signal.SIGTERM)}
            try:
                result = analyze(args.target, progress, args.scan_limit)
            finally:
                for value, handler in handlers.items(): signal.signal(value, handler)
        elif args.command in ("run", "attach"):
            if args.timeout <= 0:
                raise ValueError("timeout must be positive")
            result = capture(args.wine, args.prefix, args.session, target=getattr(args, "target", None), arguments=getattr(args, "arguments", []), pid=getattr(args, "pid", None), interactive=args.interactive, timeout=args.timeout, profile=args.profile, breakpoint=args.breakpoint, architecture=getattr(args, "arch", "x86_64"), on_hresult=args.on_hresult, trigger_action=args.trigger_action, observer=lambda event: print(json.dumps({"event": "debug", "data": event}), file=sys.stderr, flush=True))
        elif args.command == "inspect": result = summary(args.path)
        elif args.command == "symbols":
            from symbols import query
            from build_sources import source_map
            mappings = [source_map(value) for value in args.source_map] if args.source_map is not None else None
            result = query(args.path, args.pdb, args.rva, args.artifacts, args.debug_file, args.sources, args.source_file,
                           args.runner_root, mappings)
        elif args.command == "compare": result = compare(args.baseline, args.candidate)
        elif args.command == "export": result = export(args.session, args.output)
        elif args.command == "control": result = send_command(args.session, " ".join(args.action))
        elif args.command == "capabilities":
            from protocol import capabilities
            result = capabilities()
        elif args.command == "serve":
            from protocol import serve
            serve(); return
        elif args.command == "dap":
            from dap import serve
            serve(); return
        print(json.dumps({"status": True, "data": result}, indent=None if args.command == "analyze" and args.progress else 2))
    except Cancelled as error:
        print(json.dumps({'status': False, 'cancelled': True, 'error': str(error)}), file=sys.stderr)
        sys.exit(130)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": False, "error": str(error)}), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

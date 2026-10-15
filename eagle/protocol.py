import json
import sys
import threading
import subprocess
from pathlib import Path

from session import compare, export, send_command, summary
from errors import Cancelled

MAX_MESSAGE = 1024 * 1024
MAX_ID = 1024

class MessageTooLarge(ValueError):
    pass

def capabilities():
    from analysis import available
    analyzer = available()
    native = Path(__file__).resolve().parent / 'native'
    architectures = [architecture for architecture, bits in (('x86', 32), ('x86_64', 64))
                     if (native / f'eagle-debug{bits}.exe').is_file()]
    return {
        "schema": 1,
        "session_inputs": {"inspect_export": ["session directory", "exported summary", "eagle-live-v1"],
                           "maximum_report_bytes": 33554432, "comparison": "complete session directories"},
        "saved_frame_symbols": {"selection": "explicit SHA256/image mappings", "maximum_addresses": 256, "capture_values": "preserved"},
        "inline_frames": {"requires": "host llvm-symbolizer", "maximum_depth": 64, "order": "innermost-to-outermost",
                          "split_packages": "debug_files selects matching DWP/DWO inputs; requires host llvm-dwarfdump and llvm-dwp for DWO assembly",
                          "gnu_compression": "temporary ELF normalization requires host llvm-objcopy or objcopy"},
        "stdio": {"maximum_message_bytes": MAX_MESSAGE, "maximum_id_bytes": MAX_ID, "large_results": "CLI or file export"},
        "symbol_queries": {"maximum": 256, "addresses": "RVA", "resolver": "requires host binutils", "pdb": "GUID/age verification; source lookup requires host llvm-symbolizer", "arm_pe": "DWARF source lookup requires host llvm-symbolizer"},
        "split_dwarf": {"inspection": "requires host llvm-dwarfdump", "maximum_units": 256, "maximum_files": 256, "scope": "unit identity only"},
        "source_checksums": {"format": "DWARF MD5", "requires": "host llvm-dwarfdump", "maximum_files": 256, "reads": "explicit source_files only"},
        "build_sources": {"requires": "recorded Soda inventories", "maximum_files": 256, "mapping": "explicit source label and relative path"},
        "debug_architectures": architectures,
        "static_analyzer": "Soda Eagle native analysis" if analyzer else None,
        "native_static_analyzer": analyzer,
        "native_components": (["PE parser and metadata/dependency interpretation", "YARA scanner and report interpretation", "Intel lookup and plans", "suggestion merge", "recommendations", "ASAR extraction", "directory discovery"] if analyzer else ["PE identities"]) + ["ELF identities"] + (["Win32 debug engine"] if architectures else []),
        "analysis": {"available": analyzer, "asynchronous": analyzer, "cancellation": analyzer, "maximum_concurrent": 2 if analyzer else 0},
        "debug": ["launch", "attach", "process-tree", "exceptions", "registers", "all-thread-stacks", "minidump", "software-breakpoint", "source-line-breakpoint", "module-load-stop", "register-condition", "hit-count-condition", "stack-logpoint", "hardware-watchpoint", "instruction-step", "pause", "resume", "detach", "memory-read", "PE-disassembly", "DAP"] if architectures else [],
        "capture_profiles": ["crash", "process", "debug"] if architectures else [],
        "provider_profiles": {"winrt": "requires patched runner provider manifest", "dwrite": "requires patched runner provider manifest", "wait": "observed KernelBase mutex handles within each process; partial coverage; requires patched runner manifest", "com": "class object/instance activation, initialization/uninitialization and activation-only QI; requires patched runner manifest"} if architectures else {},
        "condition_language": "unsigned register or hit-count comparison with an integer constant" if architectures else None,
        "unsupported": ["arbitrary-expression-evaluation", "wait-ownership-graph", "COM-wide-QI", "identity-stages", "host-adapters", "instruction-replay", "CLR", "ARM64-debug"],
    }

def read_message(stream):
    headers = {}
    total = 0
    while True:
        line = stream.readline(8193)
        total += len(line)
        if not line:
            if headers:
                raise ValueError("truncated message headers")
            return None
        if total > 8192:
            raise ValueError("message headers exceed size limit")
        if line in (b"\r\n", b"\n"):
            break
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError("invalid message header")
        headers[name.strip().lower()] = value.strip()
    size = int(headers.get(b"content-length", b"0"))
    if size < 1 or size > MAX_MESSAGE:
        raise ValueError("invalid content length")
    body = stream.read(size)
    if len(body) != size:
        raise ValueError("truncated message")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    return value

def write_message(stream, message, limit=None):
    data = json.dumps(message).encode()
    if limit is not None and len(data) > limit:
        raise MessageTooLarge('message exceeds size limit; use CLI or file export for the full result')
    stream.write(f"Content-Length: {len(data)}\r\n\r\n".encode() + data)
    stream.flush()

def serve():
    initialized = False
    jobs = {}
    lock = threading.Lock()
    def send(value):
        with lock:
            try:
                write_message(sys.stdout.buffer, value, limit=MAX_MESSAGE)
            except MessageTooLarge:
                if 'error' not in value:
                    raise
                write_message(sys.stdout.buffer, {'id': value.get('id'), 'error': {
                    'code': value['error']['code'], 'message': 'error detail exceeds message size limit'}}, limit=MAX_MESSAGE)

    def start_job(request_id, method, params):
        if method == 'analyze' and not capabilities()['analysis']['available']:
            raise ValueError('Static analysis is not included in this build')
        if method == 'security-scan' and not (Path(__file__).resolve().parent / 'native/eagle-yara').is_file():
            raise ValueError('Static scanning is not included in this build')
        if request_id is None or not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
            raise ValueError("analysis requires a string or integer request id")
        if request_id in jobs:
            raise ValueError("request id is already active")
        if sum(job[0].is_alive() for job in jobs.values()) >= 2:
            raise ValueError("analysis concurrency limit reached")
        cancelled = threading.Event()
        def progress(text):
            if cancelled.is_set():
                raise RuntimeError("analysis cancelled")
            send({"event": "analysis.step", "request_id": request_id, "data": text})
        def run():
            try:
                if method == 'analyze':
                    from analysis import analyze
                    result = analyze(params["path"], progress, params.get("scan_limit", 50), cancelled)
                elif method == 'security-scan':
                    from analysis import scan
                    result = scan(params['path'], cancelled)
                else:
                    from session import capture
                    result = capture(params['wine'], params['prefix'], params['session'],
                                     target=params.get('target') if method == 'run' else None,
                                     pid=params.get('pid') if method == 'attach' else None,
                                     arguments=params.get('arguments', []), interactive=params.get('interactive', False),
                                     timeout=params.get('timeout', 120), profile=params.get('profile', 'crash'),
                                     architecture=params.get('architecture', 'x86_64'), breakpoint=params.get('breakpoint'),
                                     on_hresult=params.get('on_hresult'), trigger_action=params.get('trigger_action', 'snapshot'),
                                     cancellation=cancelled,
                                     observer=lambda event: send({'event': 'debug.event', 'request_id': request_id, 'data': event}))
                if cancelled.is_set():
                    raise RuntimeError("analysis cancelled")
                send({"id": request_id, "result": result})
            except (KeyError, TypeError, ValueError, OSError, RuntimeError, subprocess.SubprocessError, Cancelled) as error:
                send({"id": request_id, "error": {"code": -32800 if cancelled.is_set() else -32603 if isinstance(error, MessageTooLarge) else -32602, "message": str(error)}})
        thread = threading.Thread(target=run, daemon=True)
        jobs[request_id] = (thread, cancelled)
        thread.start()
    while True:
        jobs = {key: value for key, value in jobs.items() if value[0].is_alive()}
        try:
            request = read_message(sys.stdin.buffer)
        except (ValueError, UnicodeDecodeError) as error:
            send({"id": None, "error": {"code": -32700, "message": str(error)}})
            for thread, cancelled in jobs.values():
                cancelled.set()
                thread.join(timeout=35)
            return
        if request is None:
            for thread, cancelled in jobs.values():
                cancelled.set()
                thread.join(timeout=35)
            return
        request_id = request.get("id")
        if request_id is not None and (type(request_id) not in (str, int) or len(json.dumps(request_id).encode()) > MAX_ID):
            send({'id': None, 'error': {'code': -32600, 'message': 'request id must be a string or integer of at most 1024 encoded bytes'}})
            continue
        try:
            method = request["method"]
            params = request.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("params must be an object")
            if method == "initialize":
                if params.get("schema") != 1:
                    raise ValueError("unsupported schema")
                initialized = True
                result = capabilities()
            elif not initialized:
                raise ValueError("initialize must be called first")
            elif method in ('analyze', 'run', 'attach', 'security-scan'):
                start_job(request_id, method, params)
                continue
            elif method == "cancel":
                job = jobs.get(params["request_id"])
                if not job:
                    raise ValueError("request is not active")
                job[1].set()
                result = {"requested": True}
            elif method == "capabilities": result = capabilities()
            elif method == "inspect": result = summary(params["session"], params.get("symbol_images"))
            elif method == "symbols":
                from symbols import query
                result = query(params["path"], params.get("pdb"), params.get("rvas"), params.get("artifacts", False), params.get("debug_files"),
                               params.get('sources', False), params.get('source_files'), params.get('runner_root'), params.get('source_maps'),
                               params.get('inlines', False))
            elif method == "compare": result = compare(params["baseline"], params["candidate"])
            elif method == "export": result = export(params["session"], params["output"], params.get("symbol_images"))
            elif method == "control": result = send_command(params["session"], params["command"])
            elif method == "shutdown":
                for thread, cancelled in jobs.values():
                    cancelled.set()
                for thread, cancelled in jobs.values():
                    thread.join(timeout=35)
                send({"id": request_id, "result": None}); return
            else: raise ValueError("unknown method")
            send({"id": request_id, "result": result})
        except (KeyError, TypeError, ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
            send({"id": request_id, "error": {"code": -32603 if isinstance(error, MessageTooLarge) else -32602, "message": str(error)}})

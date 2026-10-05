import json
import sys
import threading
import subprocess
from pathlib import Path

from session import compare, export, identity, send_command, summary
from errors import Cancelled

MAX_MESSAGE = 1024 * 1024

def capabilities():
    native = Path(__file__).resolve().parent / 'native'
    analyzer = all((native / name).is_file() for name in ('eagle-analysis', 'eagle-intel', 'eagle-yara'))
    return {
        "schema": 1,
        "debug_architectures": ["x86", "x86_64"],
        "static_analyzer": "Bottles Eagle compatibility provider" if analyzer else None,
        "native_static_analyzer": False,
        "native_components": (["PE parser and metadata/dependency interpretation", "YARA scanner and report interpretation", "Intel lookup and plans", "suggestion merge", "recommendations", "ASAR extraction", "directory discovery"] if analyzer else ["PE identities"]) + ["ELF identities", "Win32 debug engine"],
        "analysis": {"available": analyzer, "asynchronous": analyzer, "cancellation": analyzer, "maximum_concurrent": 2 if analyzer else 0},
        "debug": ["launch", "attach", "process-tree", "exceptions", "registers", "all-thread-stacks", "minidump", "software-breakpoint", "source-line-breakpoint", "module-load-stop", "register-condition", "hit-count-condition", "stack-logpoint", "hardware-watchpoint", "instruction-step", "pause", "resume", "detach", "memory-read", "PE-disassembly", "DAP"],
        "capture_profiles": ["crash", "process", "debug"],
        "provider_profiles": {"winrt": "requires patched runner provider manifest", "dwrite": "requires patched runner provider manifest", "wait": "observed KernelBase mutex handles within each process; partial coverage; requires patched runner manifest", "com": "class object/instance activation, initialization/uninitialization and activation-only QI; requires patched runner manifest"},
        "condition_language": "unsigned register or hit-count comparison with an integer constant",
        "unsupported": ["arbitrary-expression-evaluation", "wait-ownership-graph", "COM-wide-QI", "identity-stages", "host-adapters", "instruction-replay", "CLR", "ARM64-debug"],
    }

def read_message(stream):
    headers = {}
    total = 0
    while True:
        line = stream.readline(8193)
        total += len(line)
        if not line:
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

def write_message(stream, message):
    data = json.dumps(message).encode()
    stream.write(f"Content-Length: {len(data)}\r\n\r\n".encode() + data)
    stream.flush()

def serve():
    initialized = False
    jobs = {}
    lock = threading.Lock()
    def send(value):
        with lock:
            write_message(sys.stdout.buffer, value)

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
                    from engine.runtime import analyze
                    result = analyze(params["path"], progress, params.get("scan_limit", 50), cancelled)
                elif method == 'security-scan':
                    from pathlib import Path
                    from engine.runtime import cancellation, run_tool
                    root = Path(__file__).resolve().parent
                    token = cancellation.set(cancelled)
                    try:
                        completed = run_tool([str(root / 'native/eagle-yara'), str(root / 'engine/eagle.yar'), str(Path(params['path']).resolve(strict=True)), '30', '--security'], capture_output=True, text=True, timeout=35)
                        if completed.returncode: raise ValueError(completed.stderr.strip())
                        result = json.loads(completed.stdout)['matches']
                    finally:
                        cancellation.reset(token)
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
                send({"id": request_id, "error": {"code": -32800 if cancelled.is_set() else -32602, "message": str(error)}})
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
            elif method == "inspect": result = summary(params["session"])
            elif method == "symbols": result = identity(params["path"])
            elif method == "compare": result = compare(params["baseline"], params["candidate"])
            elif method == "export": result = export(params["session"], params["output"])
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
            send({"id": request_id, "error": {"code": -32602, "message": str(error)}})

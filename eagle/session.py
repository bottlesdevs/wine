import collections
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import time
import re
import math

SCHEMA = 1

def windows_path(path):
    return "Z:" + str(Path(path).resolve()).replace("/", "\\")

def unix_modules(pid):
    if not isinstance(pid, int) or pid <= 0:
        raise ValueError('invalid Unix process id')
    mappings = {}
    with Path(f'/proc/{pid}/maps').open() as file:
        for count, line in enumerate(file):
            if count >= 65536:
                raise ValueError('process mapping inventory exceeds limit')
            fields = line.rstrip().split(None, 5)
            if len(fields) < 6 or not fields[5].startswith('/') or fields[5].endswith(' (deleted)'):
                continue
            address, permissions, offset, device, inode, path = fields
            mappings.setdefault(path, []).append({'range': address, 'permissions': permissions, 'offset': offset})
    modules = {}
    skipped = 0
    for path, regions in mappings.items():
        try:
            with Path(path).open('rb') as file:
                if file.read(4) != b'\x7fELF':
                    continue
            if len(modules) >= 128:
                skipped += 1
                continue
            modules[path] = {**identity(path), 'pid': pid, 'regions': regions}
        except (OSError, ValueError, subprocess.SubprocessError):
            skipped += 1
    return modules, skipped

def identity(path):
    path = Path(path).resolve(strict=True)
    digest = hashlib.sha256()
    with path.open("rb") as file:
        magic = file.read(4)
        digest.update(magic)
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    if magic == b'\x7fELF':
        native = Path(__file__).resolve().parent / 'native/eagle-elf'
        result = subprocess.run([str(native), str(path)], capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise ValueError(result.stderr.strip())
        return {'sha256': digest.hexdigest(), **json.loads(result.stdout)}
    native = Path(__file__).resolve().parent / "native/eagle-pe"
    if native.is_file():
        result = subprocess.run([str(native), str(path)], capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise ValueError(result.stderr.strip())
        value = json.loads(result.stdout)
        return {"sha256": digest.hexdigest(), **{name: value[name] for name in ("machine", "timestamp", "size", "codeview")}}
    import pefile
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
        records = []
        for debug in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            data = pe.get_data(debug.struct.AddressOfRawData, debug.struct.SizeOfData)
            if data[:4] == b"RSDS" and len(data) >= 24:
                import uuid
                records.append({"guid": str(uuid.UUID(bytes_le=data[4:20])), "age": int.from_bytes(data[20:24], "little"), "pdb": data[24:].split(b"\0")[0].decode("utf-8", "replace")})
        return {"sha256": digest.hexdigest(), "machine": pe.FILE_HEADER.Machine, "timestamp": pe.FILE_HEADER.TimeDateStamp, "size": pe.OPTIONAL_HEADER.SizeOfImage, "codeview": records}
    finally:
        pe.close()

def read_bundle(root):
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported session schema")
    events = []
    with (root / "events.jsonl").open() as file:
        for line in file:
            if len(line) > 2 * 1024 * 1024:
                raise ValueError("session event exceeds size limit")
            events.append(json.loads(line))
    return manifest, events

def summary(root):
    manifest, events = read_bundle(root)
    exits = [{key: event[key] for key in ("pid", "code")} for event in events if event["kind"] == "process_exit"]
    faults = [event for event in events if event["kind"] == "exception" and not event["first_chance"]]
    providers = [event for event in events if event['kind'] == 'provider']
    cycles = [event for event in providers if event.get('wait_graph', {}).get('cycles')]
    timeline = [event for event in events if event['kind'] not in ('provider', 'snapshot', 'dump', 'memory') and not (event['kind'] == 'exception' and event.get('internal'))]
    dumps = [{key: event[key] for key in ('seq', 'time_ms', 'kind', 'pid', 'tid', 'path', 'size') if key in event} for event in events if event['kind'] == 'dump']
    return {"manifest": manifest, "counts": dict(collections.Counter(event["kind"] for event in events)), "exits": exits, "terminal_exceptions": faults, "snapshots": [event for event in events if event["kind"] == "snapshot"], "dumps": dumps, 'providers': providers[-2000:], 'provider_selection': 'most recent 2000', 'timeline': timeline[-4096:], 'timeline_events_omitted': max(0, len(timeline) - 4096), 'provider_events_omitted': max(0, len(providers) - 2000), 'observed_wait_cycles': cycles[:100], 'wait_cycles_omitted': max(0, len(cycles) - 100)}

def fingerprint(event):
    frame = event.get("frame", {}) or {}
    return (event["kind"], event.get("code"), event.get("first_chance"), Path(event.get("path", "").replace("\\", "/")).name, frame.get("module"), frame.get("rva"))

def compare(first, second):
    a, left = read_bundle(first)
    b, right = read_bundle(second)
    x = collections.Counter(map(fingerprint, left))
    y = collections.Counter(map(fingerprint, right))
    same_input = bool(a.get("target_identity")) and all(a.get(key) == b.get(key) for key in ('target_identity', 'arguments', 'profile', 'trigger', 'interactive'))
    return {"matching_inputs": same_input, "verdict": "comparable" if same_input else "inconclusive: inputs or observers differ", "added": [{"fingerprint": list(key), "count": count} for key, count in (y-x).items()], "removed": [{"fingerprint": list(key), "count": count} for key, count in (x-y).items()]}

def redact(value, key=""):
    path_keys = {"path", "image", "file", "prefix", "wine", "arguments", "target", "pdb", "loaded_pdb", "source", "target_cwd"}
    if key in path_keys:
        return "[redacted]"
    if key in ('modules', 'unix_modules'):
        return {record["sha256"]: redact(record) for record in value.values()}
    if isinstance(value, dict):
        return {name: redact(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value

def export(root, destination):
    report = summary(root)
    output = redact(report)
    output["export"] = {"redaction": "paths and launch arguments removed", "review_required": True, "memory_and_dumps_included": False}
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as file:
        file.write(json.dumps(output, indent=2) + "\n")
    return output

def send_command(root, command):
    if any(character in command for character in ('\n', '\r', '\x00')) or len(command.encode()) > 1000:
        raise ValueError("invalid debugger command")
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3)
        client.connect(str(Path(root).resolve() / "control.sock"))
        client.sendall(command.encode() + b"\n")
        result = json.loads(client.recv(4096))
        if not result["accepted"]:
            raise ValueError(result["error"])
        return result

def capture(wine, prefix, root, target=None, arguments=(), pid=None, interactive=False, timeout=120, profile="crash", observer=None, breakpoint=None, architecture="x86_64", on_hresult=None, trigger_action="snapshot", cancellation=None, target_cwd=None, control_enabled=True):
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 86400:
        raise ValueError('timeout must be finite and between zero and one day')
    if bool(target) == bool(pid):
        raise ValueError('provide exactly one target executable or Windows process id')
    if pid is not None and (not isinstance(pid, int) or isinstance(pid, bool) or not 0 < pid <= 0xffffffff):
        raise ValueError('Windows process id is out of bounds')
    if architecture not in ('x86', 'x86_64'):
        raise ValueError('unsupported collector architecture')
    wine = Path(wine).resolve(strict=True)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError('Wine executable is unavailable')
    prefix = Path(prefix).resolve()
    root = Path(root).resolve()
    if control_enabled and len(str(root / 'control.sock').encode()) > 107:
        raise ValueError('session path exceeds Unix control socket limit')
    if breakpoint and (any(character in breakpoint for character in ('\n', '\r', '\x00')) or len(breakpoint.encode()) > 900):
        raise ValueError('invalid function breakpoint')
    ident = identity(target) if target else None
    if ident and ident["machine"] not in (0x14c, 0x8664):
        raise ValueError("this build supports x86 and x64 debug targets")
    bits = "32" if (ident and ident["machine"] == 0x14c) or (pid and architecture == "x86") else "64"
    collector = Path(__file__).resolve().parent / "native" / f"eagle-debug{bits}.exe"
    if not collector.is_file():
        raise FileNotFoundError(f"native collector is not built: {collector}")
    if profile not in ("crash", "process", "debug", "winrt", "dwrite", "com", "wait", "trace"):
        raise ValueError("unsupported capture profile")
    from waits import WaitGraph
    waits = WaitGraph()
    env = dict(os.environ, WINEPREFIX=str(prefix), WINEDEBUG="-all", WINEDLLOVERRIDES="winemenubuilder.exe=d")
    for name in ('EAGLE_PROVIDER_MASK', 'EAGLE_TRIGGER_HRESULT', 'EAGLE_TRIGGER_ACTION', 'EAGLE_TARGET_CWD', 'EAGLE_TRACE_EXCLUDE_WINE_CONHOST'):
        env.pop(name, None)
    if profile in ("winrt", "dwrite", "com", "wait", "trace"):
        providers = json.loads((wine.parent.parent / "share/eagle/providers.json").read_text())
        requested = ('winrt', 'dwrite', 'com', 'wait') if profile == 'trace' else (profile,)
        if any(bits not in providers.get('profiles', {}).get(name, []) for name in requested):
            raise ValueError("provider is not available for this runner and architecture")
        env["EAGLE_PROVIDER_MASK"] = {"winrt": "1", "dwrite": "2", "com": "4", "wait": "8", "trace": "15"}[profile]
    if profile == 'trace':
        env['EAGLE_TRACE_EXCLUDE_WINE_CONHOST'] = '1'
    if target:
        env["EAGLE_TARGET_CWD"] = windows_path(Path(target_cwd).resolve(strict=True) if target_cwd else Path(target).resolve().parent)
    if on_hresult:
        if profile not in ('winrt', 'dwrite', 'com') or not re.fullmatch(r'0x[0-9a-fA-F]{8}', on_hresult):
            raise ValueError('HRESULT trigger requires a provider profile and an eight-digit hexadecimal value')
        if trigger_action not in ('snapshot', 'dump', 'stop'):
            raise ValueError('unsupported trigger action')
        env.update(EAGLE_TRIGGER_HRESULT=on_hresult.lower(), EAGLE_TRIGGER_ACTION=trigger_action)
    mode, argument = ("attach", str(pid)) if pid else ("run", subprocess.list2cmdline([windows_path(target), *arguments]))
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / "dumps").mkdir(mode=0o700)
    manifest = {"schema": SCHEMA, "wine": str(wine), "prefix": str(prefix), "target": str(target) if target else None, "target_identity": ident, "arguments": list(arguments), "profile": profile, "interactive": interactive or bool(breakpoint), "started": time.time(), "completed": False, "dropped_events": 0, "modules": {}}
    manifest['trigger'] = {'hresult': on_hresult, 'action': trigger_action} if on_hresult else None
    manifest['target_cwd'] = str(target_cwd) if target_cwd else None
    manifest['unix_modules'] = {}
    manifest['unix_inventory'] = {'mode': 'sampled module identities', 'host_stacks_captured': False}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    control = socket.socket(socket.AF_UNIX)
    selector = selectors.DefaultSelector()
    if control_enabled:
        control.bind(str(root / "control.sock")); os.chmod(root / "control.sock", 0o600); control.listen(4)
    process = subprocess.Popen([str(wine), str(collector), mode, argument, "interactive" if manifest["interactive"] else "auto"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root / "dumps", env=env)
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, "stdout" if stream is process.stdout else "stderr")
    if control_enabled:
        selector.register(control, selectors.EVENT_READ, "control")
    buffers = {"stdout": b"", "stderr": b""}
    deadline = time.monotonic() + timeout
    count = 0
    initialized_breakpoint = False
    complete_event = False
    verified_images = {}
    resolved_frames = {}
    def image_matches(image, expected):
        stat = image.stat()
        signature = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        key = str(image.resolve())
        if verified_images.get(key) == (signature, expected):
            return True
        if identity(image) != expected:
            return False
        after = image.stat()
        if signature != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            return False
        verified_images[key] = (signature, expected)
        return True
    def native(command):
        if any(character in command for character in ('\n', '\r', '\x00')) or len(command.encode()) > 1000:
            raise ValueError('invalid debugger command')
        process.stdin.write(command.encode() + b"\n"); process.stdin.flush()
    try:
        with (root / "events.jsonl").open("x", encoding="utf-8") as output:
            while process.poll() is None or any(key.data != "control" for key in selector.get_map().values()):
                if cancellation and cancellation.is_set() and not manifest.get('cancelled') and process.poll() is None:
                    native('detach')
                    manifest['cancelled'] = True
                    deadline = time.monotonic() + 10
                if time.monotonic() > deadline and process.poll() is None:
                    if manifest.get("timeout") or manifest.get('cancelled'):
                        process.terminate()
                        raise TimeoutError("collector did not detach before its deadline")
                    else:
                        native("detach")
                        manifest["timeout"] = True
                        deadline = time.monotonic() + 10
                for key, _ in selector.select(0.1):
                    kind = key.data
                    if kind == "control":
                        client, _ = control.accept()
                        with client:
                            client.settimeout(1)
                            command = client.recv(1024).decode().strip()
                            accepted = command in ("pause", "continue", "pass", "snapshot", "dump", "step", "detach", "clear") or command.startswith(("break ", "memory ", "watch ", "condition ", "logpoint ", "source ", "module ", "remove "))
                            accepted = accepted and '\n' not in command
                            if accepted:
                                native(command)
                            client.sendall(json.dumps({"accepted": accepted, "error": None if accepted else "unknown command"}).encode())
                        continue
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if kind == "stderr":
                        manifest["discarded_stderr_bytes"] = manifest.get("discarded_stderr_bytes", 0) + len(data)
                        continue
                    buffers[kind] += data
                    if len(buffers[kind]) > 2 * 1024 * 1024:
                        raise ValueError("collector output exceeds event limit")
                    while b"\n" in buffers[kind]:
                        line, buffers[kind] = buffers[kind].split(b"\n", 1)
                        try:
                            event = json.loads(line)
                        except (ValueError, UnicodeDecodeError):
                            manifest["discarded_target_output_bytes"] = manifest.get("discarded_target_output_bytes", 0) + len(line)
                            continue
                        if not isinstance(event, dict) or "kind" not in event:
                            continue
                        if event['kind'] == 'commands_dropped':
                            manifest['dropped_commands'] = manifest.get('dropped_commands', 0) + event['count']
                        if event['kind'] in ('finished', 'detached'):
                            complete_event = True
                        if event['kind'] == 'error':
                            manifest['debugger_errors'] = manifest.get('debugger_errors', 0) + 1
                        if event['kind'] == 'process_create' and event.get('unix_pid'):
                            try:
                                modules, skipped = unix_modules(event['unix_pid'])
                                manifest['unix_modules'].update(modules)
                                manifest['unix_inventory']['skipped'] = manifest['unix_inventory'].get('skipped', 0) + skipped
                            except (OSError, ValueError):
                                manifest['unix_inventory']['unavailable'] = manifest['unix_inventory'].get('unavailable', 0) + 1
                        if event["kind"] == "provider":
                            payload = json.loads(event.pop("payload"))
                            if not isinstance(payload, dict) or payload.get("provider") not in (1, 2, 4, 8):
                                raise ValueError("unsupported provider payload")
                            if payload["provider"] == 1:
                                payload["class"] = payload.pop("subject")
                            elif payload["provider"] == 2:
                                payload["width"] = payload.pop("a")
                                payload["height"] = payload.pop("b")
                                payload["buffer_bytes"] = payload.pop("c")
                                payload["texture_type"] = payload.pop("d")
                            elif payload["provider"] == 4:
                                operation = payload.get("event")
                                if operation == 'CoInitializeEx':
                                    payload['model_requested'] = payload.pop('context')
                                    payload['apartment_requested'] = 'STA' if payload['model_requested'] & 2 else 'MTA'
                                elif operation == 'CoUninitialize':
                                    payload['initialization_depth'] = payload.pop('count')
                                elif operation == 'ActivationQueryInterface':
                                    payload['interface_index'] = payload.pop('count')
                                    payload['scope'] = 'activation only'
                                else:
                                    payload['class_context'] = payload.pop('context')
                            event["data"] = payload
                        graph = waits.observe(event)
                        if graph is not None: event['wait_graph'] = graph
                        from symbols import host_path, resolve, disassemble
                        if event["kind"] in ("process_create", "module_load"):
                            image = host_path(event.get("path", ""), prefix)
                            if image and image.is_file():
                                try:
                                    event["identity"] = identity(image)
                                    manifest["modules"][str(image.resolve())] = event["identity"]
                                    if pid and not manifest["target_identity"] and event["kind"] == "process_create":
                                        manifest["target_identity"] = event["identity"]
                                except (ValueError, OSError):
                                    event["identity_error"] = "PE identity unavailable"
                        frames = event.get("frames", [event["frame"]] if event.get("frame") else [])
                        if event['kind'] == 'exception' and not event['first_chance'] and event.get('frame'):
                            fault = event['frame']
                            image = host_path(fault.get('image', ''), prefix)
                            if image and image.is_file() and image_matches(image, manifest['modules'].get(str(image.resolve()))):
                                event['disassembly'] = disassemble(image, fault['rva'])
                        for frame in frames:
                            if frame.get("symbol") or not frame.get("rva"):
                                continue
                            image = host_path(frame.get("image", ""), prefix)
                            if not image or not image.is_file():
                                continue
                            expected = manifest["modules"].get(str(image.resolve()))
                            if not expected or not image_matches(image, expected):
                                frame["symbol_status"] = "image missing or mismatched"
                                continue
                            key = (str(image.resolve()), expected['sha256'], frame['rva'])
                            resolved = resolved_frames.get(key)
                            if resolved is None:
                                resolved = resolve(image, [frame["rva"]])
                                if len(resolved_frames) < 8192:
                                    resolved_frames[key] = resolved
                            if resolved and resolved[0]["symbol"]:
                                frame.update(resolved[0])
                            else:
                                frame["symbol_status"] = "symbols unavailable"
                        count += 1
                        if count > 1000000:
                            manifest["dropped_events"] += 1
                            continue
                        output.write(json.dumps(event) + "\n"); output.flush()
                        if observer:
                            observer(event)
                        if breakpoint and event["kind"] == "stopped" and not initialized_breakpoint:
                            native("break " + breakpoint); native("continue"); initialized_breakpoint = True
            manifest["collector_exit"] = process.wait(timeout=10)
            manifest["completed"] = complete_event and manifest["collector_exit"] == 0 and not manifest.get("timeout") and not manifest.get('cancelled')
    finally:
        if process.poll() is None:
            try:
                native("detach"); process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                process.terminate(); process.wait(timeout=10)
        selector.close(); control.close(); (root / "control.sock").unlink(missing_ok=True)
        manifest["ended"] = time.time()
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return summary(root)

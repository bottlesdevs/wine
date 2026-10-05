import datetime
import os
import json
from pathlib import Path
import re
import uuid

from session import capture, export, redact
from symbols import host_path


def trace(wine, prefix, logs, arguments, cwd=None):
    if not arguments:
        raise ValueError('provide a Wine program and its arguments')
    prefix = Path(prefix).resolve(strict=True)
    cwd = Path(cwd or os.getcwd()).resolve(strict=True)
    command = arguments[0]
    target = host_path(command, prefix)
    if target is None:
        target = cwd / command
        if not target.is_file():
            name = command if command.lower().endswith('.exe') else command + '.exe'
            target = prefix / 'drive_c/windows/system32' / name
    target = target.resolve(strict=True)
    directory = Path(logs).resolve()
    if directory != prefix / 'logs/runs':
        raise ValueError('trace logs must be stored in the bottle logs/runs directory')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = re.sub(r'[^A-Za-z0-9._-]', '_', target.stem)[:48] or 'program'
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    stem = f'{name}-{stamp}-{uuid.uuid4().hex[:12]}'
    bundle = directory / (stem + '.session')
    report = directory / (stem + '.log')
    running = directory / (stem + '.running.log')
    with os.fdopen(os.open(running, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as live:
        live.write(json.dumps({'format': 'eagle-live-v1', 'completed': False, 'review_required': True, 'memory_and_dumps_included': False, 'byte_limit': 16 * 1024 * 1024}) + '\n')
        live.flush()
        size = 0
        omitted = 0
        def observe(event):
            nonlocal size, omitted
            if event['kind'] in ('memory', 'dump'):
                return
            line = json.dumps(redact(event)) + '\n'
            length = len(line.encode())
            if size + length > 16 * 1024 * 1024:
                omitted += 1
                if omitted == 1:
                    live.write(json.dumps({'kind': 'capture_limit', 'coverage': 'partial', 'byte_limit': 16 * 1024 * 1024}) + '\n')
                    live.flush()
                return
            size += length
            live.write(line)
            live.flush()
        try:
            result = capture(wine, prefix, bundle, target=target, arguments=arguments[1:], timeout=86400, profile='trace', target_cwd=cwd, control_enabled=False, observer=observe)
        except Exception as error:
            live.write(json.dumps({'kind': 'capture_error', 'error_type': type(error).__name__, 'completed': False}) + '\n')
            live.flush()
            if (bundle / 'manifest.json').is_file() and (bundle / 'events.jsonl').is_file():
                manifest_path = bundle / 'manifest.json'
                failed = json.loads(manifest_path.read_text())
                failed['capture_error_type'] = type(error).__name__
                manifest_path.write_text(json.dumps(failed, indent=2) + '\n')
                export(bundle, report)
                running.unlink()
            raise
    export(bundle, report)
    running.unlink()
    from session import read_bundle
    manifest, events = read_bundle(bundle)
    pid = next((event['pid'] for event in events if event['kind'] == 'process_create'), None)
    code = next((event['code'] for event in events if event['kind'] == 'process_exit' and event['pid'] == pid), None)
    if not manifest['completed'] or code is None:
        raise RuntimeError(f'Trace incomplete; review {report}')
    return {'log': str(report), 'review_required': True, 'exit_code': code, 'counts': result['counts']}

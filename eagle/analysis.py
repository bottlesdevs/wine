import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

from errors import Cancelled


ROOT = Path(__file__).resolve().parent


def available():
    return all((ROOT / path).is_file() for path in (
        'native/eagle-driver', 'native/eagle-pe', 'native/eagle-analysis',
        'native/eagle-intel', 'native/eagle-yara', 'analysis.json',
        'engine/eagle.yar', 'engine/eagle-intel.sqlite'))


def scan(path, cancel=None):
    if cancel and cancel.is_set():
        raise Cancelled('analysis cancelled')
    command = [str(ROOT / 'native/eagle-yara'), str(ROOT / 'engine/eagle.yar'),
               str(Path(path).resolve(strict=True)), '30', '--security']
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            deadline = time.monotonic() + 35
            while True:
                if cancel and cancel.is_set():
                    raise Cancelled('analysis cancelled')
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, 35)
                try:
                    stdout, stderr = process.communicate(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
            if process.returncode:
                raise ValueError(stderr.strip() or 'scan failed')
            return json.loads(stdout)['matches']
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


def analyze(path, progress=None, limit=50, cancel=None):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10000:
        raise ValueError('scan limit must be between 1 and 10000')
    if cancel and cancel.is_set():
        raise Cancelled('analysis cancelled')
    if not available():
        raise ValueError('Static analysis is not included in this build')
    work = Path(os.environ.get('TMPDIR', Path.home() / '.cache/eagle/work'))
    work.mkdir(parents=True, exist_ok=True)
    request = dict(target=str(Path(path).absolute()), scan_limit=limit,
                   work=str(work), extractor_python=sys.executable)
    result = None
    pending = bytearray()
    errors = bytearray()
    with subprocess.Popen([str(ROOT / 'native/eagle-driver')], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            process.stdin.write(json.dumps(request).encode())
            process.stdin.close()
            with selectors.DefaultSelector() as selector:
                for stream in (process.stdout, process.stderr):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    if cancel and cancel.is_set():
                        raise Cancelled('analysis cancelled')
                    for key, _ in selector.select(0.1):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buffer = pending if key.fileobj is process.stdout else errors
                        buffer.extend(chunk)
                        if len(buffer) > 16 * 1024 * 1024:
                            raise ValueError('analysis output exceeds limit')
                        if buffer is errors:
                            continue
                        while b'\n' in pending:
                            line, _, remaining = pending.partition(b'\n')
                            pending[:] = remaining
                            message = json.loads(line)
                            if not isinstance(message, dict):
                                raise ValueError('invalid analysis response')
                            if result is not None:
                                raise ValueError('unexpected analysis response')
                            if message.get('event') == 'step' and isinstance(message.get('data'), str):
                                if progress:
                                    progress(message['data'])
                            elif 'event' not in message and isinstance(message.get('status'), bool):
                                result = message
                            else:
                                raise ValueError('unexpected analysis response')
                while process.poll() is None:
                    if cancel and cancel.wait(0.1):
                        raise Cancelled('analysis cancelled')
                    try:
                        process.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
            if cancel and cancel.is_set():
                raise Cancelled('analysis cancelled')
            if pending or result is None:
                raise ValueError('incomplete analysis response')
            if result.get('cancelled'):
                raise Cancelled('analysis cancelled')
            if process.returncode or not result['status']:
                raise ValueError(result.get('error') or errors.decode(errors='replace') or 'analysis failed')
            if not isinstance(result.get('data'), dict):
                raise ValueError('invalid analysis report')
            return result['data']
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

import contextvars
import logging
import os
import signal
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from errors import Cancelled

try:
    import patoolib
except ImportError:
    class MissingExtractor:
        @staticmethod
        def extract_archive(*args, **kwargs):
            raise RuntimeError("patool fallback is unavailable; install the existing Bottles extractor dependency")
    patoolib = MissingExtractor()

APP_ID = "com.usebottles.bottles"
BottleConfig = dict
callback = contextvars.ContextVar("eagle_callback", default=lambda *args: None)
scan_limit = contextvars.ContextVar("eagle_scan_limit", default=50)
cancellation = contextvars.ContextVar("eagle_cancellation", default=None)

def check_cancelled():
    event = cancellation.get()
    if event and event.is_set():
        raise Cancelled("analysis cancelled")

def run_tool(command, *, timeout, **options):
    check_cancelled()
    data = options.pop('input', None)
    capture = options.pop('capture_output', False)
    if capture:
        options.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if data is not None:
        options['stdin'] = subprocess.PIPE
    deadline = time.monotonic() + timeout
    options['start_new_session'] = True
    with subprocess.Popen(command, **options) as process:
        try:
            while True:
                check_cancelled()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    stdout, stderr = process.communicate(data, timeout=min(remaining, 0.1))
                    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                except subprocess.TimeoutExpired:
                    data = None
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()

class Paths:
    base = str(Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "bottles")
    temp = os.environ.get("TMPDIR", str(Path.home() / ".cache/eagle/work"))

class Result:
    def __init__(self, status=False, data=None):
        self.status = status
        self.data = data

Signals = SimpleNamespace(EagleStep="step", EagleFinished="finished")

class SignalManager:
    @staticmethod
    def send(kind, result):
        callback.get()(kind, result)

class Settings:
    @staticmethod
    def new(app_id):
        return Settings()

    def get_int(self, key):
        if key != "eagle-scan-limit":
            raise ValueError(key)
        return scan_limit.get()

Gio = SimpleNamespace(Settings=Settings)

def Logger():
    return logging.getLogger("eagle")

def analyze(path, progress=None, limit=50, cancel=None):
    from .analyzer import EagleManager
    if not 1 <= limit <= 10000:
        raise ValueError("scan limit must be between 1 and 10000")
    Path(Paths.temp).mkdir(parents=True, exist_ok=True)
    result = []
    def receive(kind, value):
        check_cancelled()
        if kind == "finished":
            result.append(value)
        elif progress:
            progress(value.data)
    token = callback.set(receive)
    setting = scan_limit.set(limit)
    cancelled = cancellation.set(cancel)
    try:
        manager = EagleManager({})
        manager._send_step = lambda message, delay=True: receive("step", Result(True, message))
        manager.analyze(str(Path(path).resolve(strict=True)))
        if not result:
            raise RuntimeError("analyzer returned no result")
        if not result[-1].status:
            raise ValueError(result[-1].data["error"])
        return result[-1].data
    finally:
        callback.reset(token)
        scan_limit.reset(setting)
        cancellation.reset(cancelled)

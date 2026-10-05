import base64
import json
import re
import threading
import time
from pathlib import Path

from protocol import read_message, write_message
from session import capture, send_command
from symbols import host_path

class Adapter:
    def __init__(self, input_stream, output_stream):
        self.input = input_stream
        self.output = output_stream
        self.lock = threading.Lock()
        self.changed = threading.Condition()
        self.seq = 0
        self.events = []
        self.stacks = {}
        self.thread = None
        self.root = None
        self.prefix = None
        self.stopped = None
        self.done = threading.Event()
        self.breakpoints = {}

    def send(self, value):
        with self.lock:
            self.seq += 1
            value["seq"] = self.seq
            write_message(self.output, value)

    def event(self, name, body=None):
        self.send({"type": "event", "event": name, "body": body or {}})

    def observed(self, value):
        with self.changed:
            self.events.append(value)
            if value["kind"] == "snapshot": self.stacks[value["tid"]] = value
            if value["kind"] == "stopped": self.stopped = value
            self.changed.notify_all()
        if value["kind"] == "stopped":
            reason = "breakpoint" if value["reason"] == "module" else value["reason"]
            self.event("stopped", {"reason": reason, "threadId": value["tid"], "allThreadsStopped": True})
        elif value["kind"] == "process_exit":
            self.event("exited", {"exitCode": value["code"]})
        elif value["kind"] == "error":
            self.event("output", {"category": "stderr", "output": f"{value['operation']}: Win32 error {value['winerror']}\n"})

    def wait(self, predicate, after=0):
        deadline = time.monotonic() + 10
        with self.changed:
            while time.monotonic() < deadline:
                for value in self.events[after:]:
                    if predicate(value): return value
                self.changed.wait(max(0, deadline - time.monotonic()))
        raise RuntimeError("debugger did not acknowledge the operation")

    def start(self, args, attach=False):
        if self.thread and self.thread.is_alive():
            raise ValueError("a debug session is already active")
        self.root = Path(args["session"]).resolve()
        self.prefix = args["prefix"]
        self.done.clear()
        with self.changed:
            self.events.clear()
            self.stacks.clear()
            self.stopped = None
            self.breakpoints.clear()
        def run():
            try:
                capture(args["wine"], self.prefix, self.root, target=None if attach else args.get("program"), arguments=args.get("args", []), pid=args.get("processId") if attach else None, architecture=args.get('architecture', 'x86_64'), interactive=True, timeout=args.get("timeout", 3600), observer=self.observed)
            except (ValueError, OSError, RuntimeError) as error:
                self.event("output", {"category": "stderr", "output": str(error) + "\n"})
            finally:
                self.done.set()
                self.event("terminated")
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.wait(lambda event: event["kind"] == "stopped")
        self.event("initialized")

    def control(self, command):
        if not self.root:
            raise ValueError("no active session")
        return send_command(self.root, command)

    def remove_breakpoint(self, address):
        after = len(self.events)
        self.control("remove " + address)
        event = self.wait(lambda event: event["kind"] in ("breakpoint_removed", "error"), after)
        if event["kind"] == "error":
            raise RuntimeError("debugger could not remove a breakpoint")

    def condition(self, item):
        if not isinstance(item, dict): raise ValueError("breakpoint must be an object")
        if item.get("logMessage"):
            raise ValueError("DAP log messages are not supported in this build")
        if item.get("condition") and item.get("hitCondition"):
            raise ValueError("use either a register condition or a hit count")
        if item.get("condition"):
            condition = item["condition"]
            match = re.fullmatch(r'([a-z][a-z0-9]*)\s*(==|!=|<=|>=|<|>)\s*(0x[0-9a-fA-F]+|[0-9]+)', condition) if isinstance(condition, str) else None
            if not match:
                raise ValueError("use an unsigned register comparison, such as rcx == 5")
            value = int(match[3], 16 if match[3].startswith("0x") else 10)
            if value > 0xffffffffffffffff: raise ValueError("register comparison exceeds 64 bits")
            return f"{match[1]} {match[2]} {value:x}"
        if item.get("hitCondition"):
            hit = str(item["hitCondition"])
            if not hit.isascii() or not hit.isdigit() or not 0 < int(hit) <= 0xffffffffffffffff:
                raise ValueError("hit condition must be a positive 64-bit hit count")
            return f"hits == {int(hit):x}"
        return None

    def request(self, command, args):
        if not isinstance(args, dict): raise ValueError("request arguments must be an object")
        if command == "initialize":
            return {"supportsConfigurationDoneRequest": True, "supportsFunctionBreakpoints": True, "supportsConditionalBreakpoints": True, "supportsHitConditionalBreakpoints": True, "supportsReadMemoryRequest": True, "supportsSteppingGranularity": True, "supportsTerminateRequest": False, "supportsStepBack": False, "supportsEvaluateForHovers": False}
        if command in ("launch", "attach"):
            self.start(args, command == "attach"); return {}
        if command == "configurationDone": self.control("continue"); return {}
        if command in ("setFunctionBreakpoints", "setBreakpoints"):
            if command == "setBreakpoints" and not isinstance(args.get("source"), dict):
                raise ValueError("source must be an object with a file path")
            source = args["source"].get("path") if command == "setBreakpoints" else None
            if command == "setBreakpoints" and (not isinstance(source, str) or not source or len(source.encode()) >= 260 or any(char in source for char in "\r\n\0")):
                raise ValueError("source must be a file path shorter than 260 bytes")
            group = (command, source)
            items = args.get("breakpoints", [])
            if not isinstance(items, list) or len(items) > 128:
                raise ValueError("at most 128 breakpoints may be requested")
            owned = self.breakpoints.setdefault(group, set())
            for address in list(owned):
                self.remove_breakpoint(address)
                owned.remove(address)
            values = []
            for item in items:
                addresses = set()
                try:
                    condition = self.condition(item)
                    if source:
                        line = item.get("line")
                        if type(line) is not int or not 0 < line <= 0xffffffff:
                            raise ValueError("source line must be a positive integer")
                        instruction = f"source {source} {line}"
                        expected = "source_breakpoint_set"
                    else:
                        name = item.get("name")
                        if not isinstance(name, str) or not name or len(name.encode()) > 512 or any(char in name for char in "\r\n\0"):
                            raise ValueError("function name is missing or too long")
                        instruction = "break " + name
                        expected = "breakpoint_set"
                    after = len(self.events)
                    self.control(instruction)
                    event = self.wait(lambda event: event["kind"] in (expected, "error"), after)
                    if event["kind"] == "error":
                        raise ValueError("source line or function could not be resolved")
                    addresses = set(event["addresses"] if source else [event["address"]])
                    existing = set().union(*self.breakpoints.values())
                    if addresses & existing:
                        addresses -= existing
                        raise ValueError("address already belongs to another breakpoint")
                    if condition:
                        for address in addresses:
                            after = len(self.events)
                            self.control(f"condition {address} {condition}")
                            event = self.wait(lambda event: event["kind"] in ("condition_set", "error"), after)
                            if event["kind"] == "error":
                                raise ValueError("register condition is unavailable for this architecture")
                    owned.update(addresses)
                    value = {"verified": True, "instructionReference": min(addresses, key=lambda address: int(address, 0))}
                    if source: value.update({"source": args["source"], "line": line})
                    values.append(value)
                except ValueError as error:
                    for address in addresses: self.remove_breakpoint(address)
                    values.append({"verified": False, "message": str(error)})
            return {"breakpoints": values}
        if command in ("continue", "stepIn"):
            if command == "stepIn" and args.get("granularity") != "instruction":
                raise ValueError("this adapter currently supports instruction stepping")
            self.control("continue" if command == "continue" else "step")
            self.stacks.clear()
            self.stopped = None
            return {"allThreadsContinued": True}
        if command == "pause": self.control("pause"); return {}
        if command == "disconnect":
            if self.thread and self.thread.is_alive():
                if not self.done.is_set(): self.control("detach")
                self.thread.join(timeout=10)
            return {}
        if command in ("threads", "stackTrace"):
            if not self.stopped: raise ValueError("target is not stopped")
            after = len(self.events)
            self.control("snapshot")
            self.wait(lambda event: event["kind"] == "snapshot_complete", after)
            if command == "threads":
                return {"threads": [{"id": tid, "name": f"Wine thread {tid}"} for tid in self.stacks]}
            tid = args["threadId"]
            self.wait(lambda event: event["kind"] == "snapshot" and event["tid"] == tid, after)
            frames = self.stacks[tid]["frames"]
            values = []
            for index, frame in enumerate(frames):
                value = {"id": tid * 256 + index, "name": frame.get("symbol") or (frame.get("module", "unknown") + "+" + frame.get("rva", "?")), "line": frame.get("line", 0), "column": 0, "instructionPointerReference": frame["address"]}
                if frame.get("file"):
                    path = host_path(frame["file"], self.prefix)
                    value["source"] = {"name": path.name, "path": str(path)} if path else {"name": frame["file"]}
                values.append(value)
            start = args.get("startFrame", 0)
            return {"stackFrames": values[start:start+args.get("levels", len(values))], "totalFrames": len(values)}
        if command == "scopes":
            return {"scopes": [{"name": "Registers", "variablesReference": args["frameId"] // 256, "expensive": False}]}
        if command == "variables":
            registers = self.stacks.get(args["variablesReference"], {}).get("registers", {})
            return {"variables": [{"name": name, "value": str(value), "variablesReference": 0} for name, value in registers.items()]}
        if command == "readMemory":
            count = args["count"]
            address = int(args["memoryReference"], 0) + args.get("offset", 0)
            if not 0 < count <= 4096 or address < 0: raise ValueError("memory request out of bounds")
            after = len(self.events)
            self.control(f"memory {address:x} {count}")
            event = self.wait(lambda event: event["kind"] in ("memory", "error"), after)
            if event["kind"] == "error": raise ValueError("memory is not readable")
            return {"address": hex(address), "data": base64.b64encode(bytes.fromhex(event["hex"])).decode()}
        raise ValueError("unsupported DAP request: " + command)

    def serve(self):
        try:
            while True:
                request = read_message(self.input)
                if request is None: break
                if request.get("type") != "request": continue
                response = {"type": "response", "request_seq": request["seq"], "command": request["command"]}
                try:
                    response["body"] = self.request(request["command"], request.get("arguments", {}))
                    response["success"] = True
                except (ValueError, KeyError, OSError, RuntimeError) as error:
                    response["success"] = False; response["message"] = str(error)
                self.send(response)
        finally:
            if self.thread and self.thread.is_alive():
                if not self.done.is_set(): self.control("detach")
                self.thread.join(timeout=10)

def serve():
    import sys
    Adapter(sys.stdin.buffer, sys.stdout.buffer).serve()

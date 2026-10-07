import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(os.environ["EAGLE_TEST_ROOT"])
PACKAGE = Path(os.environ["EAGLE_PACKAGE"])
CLI = PACKAGE / "bin/eagle"
WINE = os.environ["EAGLE_TEST_WINE"]
sys.path.insert(0, str(PACKAGE / "lib/eagle"))
from session import read_bundle, send_command, windows_path
from protocol import read_message, write_message

class Integration(unittest.TestCase):
    def launch(self, name, target="target64.exe", argument="crash", interactive=False):
        bundle = ROOT / name
        command = [str(CLI), "run", "--wine", WINE, "--prefix", str(ROOT / "prefix"), "--session", str(bundle), "--timeout", "30"]
        if interactive:
            command.append("--interactive")
        command += [str(ROOT / target), *(argument if isinstance(argument, list) else [argument])]
        log = (ROOT / (name + ".stderr")).open("w")
        output = (ROOT / (name + ".json")).open("w")
        process = subprocess.Popen(command, stdout=output, stderr=log)
        self.addCleanup(output.close); self.addCleanup(log.close)
        self.addCleanup(lambda: process.poll() is None and process.terminate())
        return process, bundle

    def wait_event(self, root, kind, after=0):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            path = root / "events.jsonl"
            if path.is_file():
                for line in path.read_text().splitlines():
                    event = json.loads(line)
                    if event["kind"] == kind and event["seq"] > after:
                        return event
            time.sleep(0.05)
        self.fail(f"{kind} not observed in {root}")

    def test_crash_symbols_dumps_and_repeatability(self):
        for bits in (64, 32):
            for attempt in range(3):
                process, root = self.launch(f"crash-{bits}-{attempt}", f"target{bits}.exe")
                self.assertEqual(process.wait(timeout=40), 0)
                manifest, events = read_bundle(root)
                self.assertTrue(manifest["completed"])
                faults = [item for item in events if item["kind"] == "exception" and item["code"] == "0xc0000005"]
                self.assertEqual([item["first_chance"] for item in faults], [True, False])
                self.assertEqual(faults[-1]['access'], 'write')
                self.assertEqual(faults[-1]['fault_address'], '0x0')
                self.assertEqual(faults[-1]['disassembly']['status'], 'available')
                self.assertFalse(faults[-1]['disassembly']['runtime_bytes_verified'])
                self.assertTrue(faults[-1]['disassembly']['instructions'])
                stack = next(item for item in events if item["kind"] == "snapshot")
                self.assertEqual(stack["frames"][0]["symbol"], "eagle_crash")
                self.assertEqual(stack["frames"][0]["line"], 16)
                self.assertGreaterEqual(len(stack["frames"]), 4)
                dump = next(item for item in events if item["kind"] == "dump")
                self.assertEqual((root / "dumps" / dump["path"]).read_bytes()[:4], b"MDMP")
                self.assertEqual(next(item for item in events if item["kind"] == "process_exit")["code"], 0xc0000005)
                self.assertEqual([item["seq"] for item in events], list(range(1, len(events)+1)))

    def test_parent_exit_does_not_drop_child(self):
        process, root = self.launch("child-tree", argument="child")
        self.assertEqual(process.wait(timeout=40), 0)
        _, events = read_bundle(root)
        self.assertEqual(sum(item["kind"] == "process_create" for item in events), 2)
        self.assertEqual(sorted(item["code"] for item in events if item["kind"] == "process_exit"), [0, 7])

    def test_multithread_logpoints_do_not_lose_hits(self):
        for attempt in range(3):
            process, root = self.launch(f'threads-{attempt}', argument='threads', interactive=True)
            self.wait_event(root, 'stopped')
            send_command(root, 'break eagle_checkpoint')
            point = self.wait_event(root, 'breakpoint_set')
            send_command(root, 'logpoint ' + point['address'])
            self.wait_event(root, 'logpoint_set')
            send_command(root, 'continue')
            self.assertEqual(process.wait(timeout=40), 0)
            manifest, events = read_bundle(root)
            self.assertTrue(manifest['completed'])
            hits = [item for item in events if item['kind'] == 'breakpoint_log']
            self.assertEqual(len(hits), 41)
            self.assertEqual([item['hits'] for item in hits], list(range(1, 42)))
            snapshots = [item for item in events if item['kind'] == 'snapshot']
            completions = [item for item in events if item['kind'] == 'snapshot_complete']
            self.assertEqual(len(snapshots), 41)
            self.assertEqual([item['tid'] for item in snapshots], [item['tid'] for item in hits])
            self.assertTrue(all(item['scope'] == 'thread' for item in completions))
            self.assertEqual(next(item['code'] for item in events if item['kind'] == 'process_exit'), 0)
            self.assertFalse([item for item in events if item['kind'] == 'error'])

    def test_clear_at_breakpoint_preserves_execution(self):
        process, root = self.launch('clear-pending', argument='normal', interactive=True)
        initial = self.wait_event(root, 'stopped')
        send_command(root, 'break eagle_checkpoint')
        self.wait_event(root, 'breakpoint_set')
        send_command(root, 'continue')
        hit = self.wait_event(root, 'stopped', initial['seq'])
        self.assertEqual(hit['reason'], 'breakpoint')
        send_command(root, 'clear')
        self.wait_event(root, 'breakpoints_cleared')
        send_command(root, 'continue')
        self.assertEqual(process.wait(timeout=40), 0)
        _, events = read_bundle(root)
        self.assertEqual(next(item['code'] for item in events if item['kind'] == 'process_exit'), 0)

    def test_source_breakpoint_and_module_load_stop(self):
        process, root = self.launch('source-line', argument='normal', interactive=True)
        initial = self.wait_event(root, 'stopped')
        send_command(root, 'source target.c 9')
        registered = self.wait_event(root, 'source_breakpoint_set')
        self.assertTrue(registered['addresses'])
        send_command(root, 'continue')
        stopped = self.wait_event(root, 'stopped', initial['seq'])
        self.assertEqual(stopped['reason'], 'breakpoint')
        send_command(root, 'snapshot')
        stack = self.wait_event(root, 'snapshot', stopped['seq'])
        self.assertEqual(stack['frames'][0]['symbol'], 'eagle_checkpoint')
        send_command(root, 'clear')
        self.wait_event(root, 'breakpoints_cleared')
        send_command(root, 'continue')
        self.assertEqual(process.wait(timeout=40), 0)
        process, root = self.launch('module-load', argument='module', interactive=True)
        initial = self.wait_event(root, 'stopped')
        send_command(root, 'module wtsapi32.dll')
        self.wait_event(root, 'module_breakpoint_set')
        send_command(root, 'continue')
        stopped = self.wait_event(root, 'stopped', initial['seq'])
        self.assertEqual(stopped['reason'], 'module')
        send_command(root, 'continue')
        self.assertEqual(process.wait(timeout=40), 0)

    def test_attach_pause_snapshot_detach(self):
        marker = ROOT / 'attach-marker'
        environment = dict(os.environ, WINEPREFIX=str(ROOT / 'prefix'), WINEDEBUG='-all')
        with subprocess.Popen([WINE, str(ROOT / 'target64.exe'), 'attach', windows_path(marker)], env=environment, stdout=subprocess.PIPE) as target:
            self.addCleanup(lambda: target.poll() is None and target.terminate())
            pid = int(target.stdout.readline())
            root = ROOT / 'attached'
            with subprocess.Popen([str(CLI), 'attach', '--wine', WINE, '--prefix', str(ROOT / 'prefix'), '--session', str(root), '--interactive', '--timeout', '30', str(pid)], stdout=subprocess.DEVNULL) as collector:
                initial = self.wait_event(root, 'stopped')
                send_command(root, 'continue')
                time.sleep(0.1)
                send_command(root, 'pause')
                paused = self.wait_event(root, 'stopped', initial['seq'])
                self.assertEqual(paused['reason'], 'pause')
                send_command(root, 'snapshot')
                self.wait_event(root, 'snapshot_complete', paused['seq'])
                send_command(root, 'detach')
                self.assertEqual(collector.wait(timeout=40), 0)
            self.assertEqual(target.wait(timeout=10), 0)
            self.assertEqual(marker.read_bytes(), b'alive')

    def test_break_snapshot_memory_step_resume(self):
        process, root = self.launch("interactive", argument="normal", interactive=True)
        first = self.wait_event(root, "stopped")
        send_command(root, "break eagle_checkpoint")
        breakpoint = self.wait_event(root, "breakpoint_set")
        send_command(root, "memory " + breakpoint["address"] + " 1")
        memory = self.wait_event(root, "memory")
        self.assertEqual(memory["hex"], "cc")
        send_command(root, "snapshot")
        self.wait_event(root, "snapshot")
        send_command(root, "step")
        stepped = self.wait_event(root, "stopped", first["seq"])
        self.assertEqual(stepped["reason"], "step")
        send_command(root, "continue")
        hit = self.wait_event(root, "stopped", stepped["seq"])
        self.assertEqual(hit["reason"], "breakpoint")
        send_command(root, "snapshot")
        captured = self.wait_event(root, "snapshot", hit["seq"])
        self.assertEqual(captured["frames"][0]["symbol"], "eagle_checkpoint")
        send_command(root, "continue")
        self.assertEqual(process.wait(timeout=40), 0)

    def test_backend_framing_and_invalid_schema(self):
        process = subprocess.Popen([str(CLI), "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and process.terminate())
        write_message(process.stdin, {"id": 1, "method": "initialize", "params": {"schema": 999}})
        self.assertIn("error", read_message(process.stdout))
        write_message(process.stdin, {"id": 2, "method": "initialize", "params": {"schema": 1}})
        self.assertEqual(read_message(process.stdout)["result"]["schema"], 1)
        write_message(process.stdin, {"id": 3, "method": "shutdown"})
        self.assertIsNone(read_message(process.stdout)["result"])
        self.assertEqual(process.wait(timeout=5), 0)
        process.stdin.close(); process.stdout.close()

    def test_conditional_breakpoints_and_logpoints(self):
        for label, expression, stops, logging in [('match', 'rcx == 5', True, False), ('skip', 'rcx == 999', False, False), ('log', 'hits == 1', False, True)]:
            process, root = self.launch('condition-' + label, argument='normal', interactive=True)
            initial = self.wait_event(root, 'stopped')
            send_command(root, 'break eagle_checkpoint')
            point = self.wait_event(root, 'breakpoint_set')
            register, operator, value = expression.split()
            send_command(root, f'condition {point["address"]} {register} {operator} {int(value):x}')
            self.wait_event(root, 'condition_set')
            if logging:
                send_command(root, 'logpoint ' + point['address'])
                self.wait_event(root, 'logpoint_set')
            send_command(root, 'continue')
            if stops:
                self.wait_event(root, 'stopped', initial['seq'])
                send_command(root, 'snapshot')
                stack = self.wait_event(root, 'snapshot', initial['seq'])
                self.assertEqual(stack['registers']['cx'], '0x5')
                send_command(root, 'continue')
            self.assertEqual(process.wait(timeout=40), 0)
            _, events = read_bundle(root)
            self.assertEqual(sum(item['kind'] == 'stopped' for item in events), 2 if stops else 1)
            self.assertEqual(sum(item['kind'] == 'breakpoint_log' for item in events), 1 if logging else 0)

    def test_dap_real_launch_function_stop_and_stack(self):
        process = subprocess.Popen([str(CLI), "dap"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and process.terminate())
        def request(seq, command, arguments=None):
            write_message(process.stdin, {"seq": seq, "type": "request", "command": command, "arguments": arguments or {}})
            while True:
                message = read_message(process.stdout)
                self.assertIsNotNone(message)
                if message["type"] == "response" and message["request_seq"] == seq:
                    self.assertTrue(message["success"], message)
                    return message["body"]
        self.assertTrue(request(1, "initialize")["supportsFunctionBreakpoints"])
        request(2, "launch", {"wine": WINE, "prefix": str(ROOT / "prefix"), "session": str(ROOT / "dap"), "program": str(ROOT / "target64.exe"), "args": ["normal"]})
        self.assertTrue(request(3, "setFunctionBreakpoints", {"breakpoints": [{"name": "eagle_checkpoint"}]})["breakpoints"][0]["verified"])
        request(4, "configurationDone")
        while True:
            message = read_message(process.stdout)
            if message.get("event") == "stopped":
                tid = message["body"]["threadId"]; break
        stack = request(5, "stackTrace", {"threadId": tid})
        self.assertEqual(stack["stackFrames"][0]["name"], "eagle_checkpoint")
        self.assertGreaterEqual(stack["totalFrames"], 4)
        request(6, "continue", {"threadId": tid})
        while read_message(process.stdout).get("event") != "terminated":
            pass
        request(7, "disconnect")
        process.stdin.close()
        self.assertEqual(process.wait(timeout=15), 0)
        process.stdout.close()

    def test_dap_source_stop_x86_and_x64(self):
        for bits, architecture in ((32, "x86"), (64, "x86_64")):
            process = subprocess.Popen([str(CLI), "dap"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self.addCleanup(lambda process=process: process.poll() is None and process.terminate())
            def request(seq, command, arguments=None):
                write_message(process.stdin, {"seq": seq, "type": "request", "command": command, "arguments": arguments or {}})
                while True:
                    message = read_message(process.stdout)
                    self.assertIsNotNone(message)
                    if message["type"] == "response" and message["request_seq"] == seq:
                        self.assertTrue(message["success"], message)
                        return message["body"]
            request(1, "initialize")
            request(2, "launch", {"wine": WINE, "prefix": str(ROOT / "prefix"), "session": str(ROOT / f"dap-source-hit-{bits}"), "program": str(ROOT / f"target{bits}.exe"), "architecture": architecture, "args": ["normal"]})
            result = request(3, "setBreakpoints", {"source": {"path": str(Path(__file__).with_name("target.c"))}, "breakpoints": [{"line": 10, "hitCondition": "1"}]})
            self.assertTrue(result["breakpoints"][0]["verified"])
            request(4, "configurationDone")
            while True:
                message = read_message(process.stdout)
                if message.get("event") == "stopped":
                    self.assertEqual(message["body"]["reason"], "breakpoint")
                    tid = message["body"]["threadId"]; break
            frame = request(5, "stackTrace", {"threadId": tid})["stackFrames"][0]
            self.assertEqual(frame["name"].lstrip("_"), "eagle_checkpoint")
            self.assertEqual(frame["line"], 10)
            self.assertEqual(frame["source"]["name"], "target.c")
            request(6, "setBreakpoints", {"source": {"path": str(Path(__file__).with_name("target.c"))}, "breakpoints": [{"line": 10, "hitCondition": "1"}]})
            request(7, "continue", {"threadId": tid})
            while True:
                message = read_message(process.stdout)
                self.assertNotEqual(message.get("event"), "stopped", "replacement retrapped the current source instruction")
                if message.get("event") == "terminated": break
            request(8, "disconnect")
            process.stdin.close()
            self.assertEqual(process.wait(timeout=15), 0)
            process.stdout.close()
            _, events = read_bundle(ROOT / f"dap-source-hit-{bits}")
            self.assertEqual(sum(item["kind"] == "stopped" for item in events), 2)

    def test_dap_source_replacement_and_function_ownership(self):
        process = subprocess.Popen([str(CLI), "dap"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and process.terminate())
        def request(seq, command, arguments=None):
            write_message(process.stdin, {"seq": seq, "type": "request", "command": command, "arguments": arguments or {}})
            while True:
                message = read_message(process.stdout)
                self.assertIsNotNone(message)
                if message["type"] == "response" and message["request_seq"] == seq:
                    self.assertTrue(message["success"], message)
                    return message["body"]
        request(1, "initialize")
        request(2, "launch", {"wine": WINE, "prefix": str(ROOT / "prefix"), "session": str(ROOT / "dap-source"), "program": str(ROOT / "target64.exe"), "args": ["normal"]})
        source = {"path": str(Path(__file__).with_name("target.c"))}
        def sources(seq, items):
            return request(seq, "setBreakpoints", {"source": source, "breakpoints": items})["breakpoints"]
        self.assertTrue(request(3, "setFunctionBreakpoints", {"breakpoints": [{"name": "eagle_checkpoint"}]})["breakpoints"][0]["verified"])
        # An alias must not change or remove a function breakpoint owned elsewhere.
        self.assertFalse(sources(4, [{"line": 9}])[0]["verified"])
        request(5, "configurationDone")
        while True:
            message = read_message(process.stdout)
            if message.get("event") == "stopped":
                tid = message["body"]["threadId"]; break
        self.assertEqual(request(6, "stackTrace", {"threadId": tid})["stackFrames"][0]["name"], "eagle_checkpoint")
        function = request(7, "setFunctionBreakpoints", {"breakpoints": [{"name": "eagle_crash"}]})["breakpoints"][0]
        self.assertTrue(function["verified"])
        self.assertFalse(sources(8, [{"line": 9, "condition": "notaregister == 5"}])[0]["verified"])
        self.assertTrue(sources(9, [{"line": 9}])[0]["verified"])
        self.assertFalse(sources(10, [{"line": 100000}])[0]["verified"])
        self.assertTrue(sources(11, [{"line": 9, "hitCondition": "1"}])[0]["verified"])
        self.assertFalse(sources(12, [{"line": 9, "logMessage": "unsupported"}])[0]["verified"])
        sources(13, [])
        request(14, "continue", {"threadId": tid})
        while read_message(process.stdout).get("event") != "terminated": pass
        request(15, "disconnect")
        process.stdin.close()
        self.assertEqual(process.wait(timeout=15), 0)
        process.stdout.close()
        _, events = read_bundle(ROOT / "dap-source")
        self.assertEqual(next(item["code"] for item in events if item["kind"] == "process_exit"), 0)
        self.assertEqual(sum(item["kind"] == "stopped" for item in events), 2)
        self.assertNotIn(function["instructionReference"], [item["address"] for item in events if item["kind"] == "breakpoint_removed"])

    def test_hardware_watchpoint_and_capacity(self):
        process, root = self.launch("watchpoint", argument="normal", interactive=True)
        self.wait_event(root, "stopped")
        listing = subprocess.check_output(["x86_64-w64-mingw32-nm", str(ROOT / "target64.exe")], text=True)
        address = next(line.split()[0] for line in listing.splitlines() if line.endswith(" eagle_value"))
        send_command(root, "watch " + address + " 4 write")
        self.wait_event(root, "watchpoint_set")
        send_command(root, "continue")
        hit = self.wait_event(root, "watchpoint_hit")
        self.assertEqual(hit["slots"], 1)
        self.wait_event(root, "stopped", hit["seq"])
        send_command(root, "memory " + address + " 4")
        memory = self.wait_event(root, "memory", hit["seq"])
        self.assertEqual(memory["hex"], "2a000000")
        send_command(root, "continue")
        self.assertEqual(process.wait(timeout=40), 0)

    def test_detach_keeps_target_alive(self):
        marker = ROOT / "detached-marker"
        process, root = self.launch("detach", argument=["wait", windows_path(marker)], interactive=True)
        self.wait_event(root, "stopped")
        send_command(root, "break eagle_checkpoint")
        self.wait_event(root, "breakpoint_set")
        send_command(root, "detach")
        self.wait_event(root, "detached")
        self.assertEqual(process.wait(timeout=40), 0)
        self.assertEqual(marker.read_bytes(), b"alive")

if __name__ == "__main__":
    unittest.main(verbosity=2)

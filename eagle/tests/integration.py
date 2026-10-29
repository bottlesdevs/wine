import hashlib
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
    def launch(self, name, target="target64.exe", argument="crash", interactive=False, timeout=30, profile="crash"):
        bundle = ROOT / name
        command = [str(CLI), "run", "--wine", WINE, "--prefix", str(ROOT / "prefix"), "--session", str(bundle), "--timeout", str(timeout), "--profile", profile]
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

    def test_null_call_retains_fault_and_unwinds_callers(self):
        for bits in (64, 32):
            process, root = self.launch(f"nullcall-{bits}", f"target{bits}.exe", "nullcall")
            self.assertEqual(process.wait(timeout=40), 0)
            manifest, events = read_bundle(root)
            self.assertTrue(manifest["completed"])
            self.assertEqual(manifest["dropped_events"], 0)
            fault = next(item for item in events if item["kind"] == "exception" and not item["first_chance"])
            self.assertEqual(fault["access"], "execute")
            self.assertEqual(fault["fault_address"], "0x0")
            stack = next(item for item in events if item["kind"] == "snapshot" and item["tid"] == fault["tid"])
            self.assertEqual(stack["registers"]["ip"], "0x0")
            self.assertEqual(stack["frames"][0]["address"], "0x0")
            self.assertTrue(stack["initial_leaf_return"])
            self.assertEqual(stack["null_call_return_status"], "recovered")
            self.assertEqual(stack["unwind"], "null-call-return+dbghelp")
            self.assertEqual([item["symbol"] for item in stack["frames"][1:4]],
                             ["eagle_null_call", "eagle_null_parent", "main"])
            self.assertTrue(all(item.get("line", 0) > 0 for item in stack["frames"][1:4]))

    def test_null_call_captures_stack_before_exception_handlers(self):
        for bits in (64, 32):
            process, root = self.launch(f"null-handler-{bits}", f"target{bits}.exe", "nullcall-handler")
            self.assertEqual(process.wait(timeout=40), 0)
            manifest, events = read_bundle(root)
            self.assertTrue(manifest["completed"])
            self.assertEqual(manifest["dropped_events"], 0)
            faults = [item for item in events if item["kind"] == "exception" and item["code"] == "0xc0000005"]
            self.assertEqual([item["first_chance"] for item in faults], [True, False])
            stacks = [item for item in events if item["kind"] == "snapshot" and item["tid"] == faults[0]["tid"]]
            self.assertEqual(len(stacks), 2)
            self.assertLess(faults[0]["seq"], stacks[0]["seq"])
            self.assertLess(stacks[0]["seq"], faults[1]["seq"])
            self.assertLess(faults[1]["seq"], stacks[1]["seq"])
            for stack in stacks:
                self.assertEqual(stack["registers"]["ip"], "0x0")
                self.assertEqual(stack["frames"][0]["address"], "0x0")
            self.assertTrue(stacks[0]["initial_leaf_return"])
            self.assertEqual([item["symbol"] for item in stacks[0]["frames"][1:4]],
                             ["eagle_null_call", "eagle_null_parent", "main"])
            self.assertFalse(stacks[1]["initial_leaf_return"])
            self.assertEqual(stacks[0]["null_call_return_status"], "recovered")
            self.assertEqual(stacks[1]["null_call_return_status"], "stack-top-zero")
            self.assertEqual(next(item for item in events if item["kind"] == "process_exit")["code"], 0xc0000005)

    def test_handled_null_call_retains_first_chance_stack(self):
        for bits in (64, 32):
            process, root = self.launch(f"null-handled-{bits}", f"target{bits}.exe", "nullcall-handled")
            self.assertEqual(process.wait(timeout=40), 0)
            manifest, events = read_bundle(root)
            self.assertTrue(manifest["completed"])
            self.assertEqual(manifest["dropped_events"], 0)
            faults = [item for item in events if item["kind"] == "exception" and item["code"] == "0xc0000005"]
            self.assertEqual([item["first_chance"] for item in faults], [True])
            stack = next(item for item in events if item["kind"] == "snapshot")
            self.assertEqual(stack["tid"], faults[0]["tid"])
            self.assertGreater(stack["seq"], faults[0]["seq"])
            self.assertTrue(stack["initial_leaf_return"])
            self.assertEqual(stack["frames"][1]["symbol"], "eagle_null_call")
            self.assertFalse(any(item["kind"] == "dump" for item in events))
            self.assertEqual(next(item for item in events if item["kind"] == "process_exit")["code"], 0)

    def test_wine_debug_channel_lookup_with_and_without_loader_tracing(self):
        for bits in (32, 64):
            for profile in ('crash', 'loader'):
                with self.subTest(bits=bits, profile=profile):
                    name = f'debug-flags-{bits}-{profile}'
                    marker = ROOT / (name + '.result.json')
                    process, root = self.launch(name, f'target{bits}.exe',
                                                ['debug-flags', windows_path(marker, ROOT / 'prefix')], profile=profile)
                    self.assertEqual(process.wait(timeout=40), 0)
                    manifest, events = read_bundle(root)
                    self.assertTrue(manifest['completed'])
                    self.assertEqual(manifest['dropped_events'], 0)
                    self.assertEqual([item['code'] for item in events if item['kind'] == 'process_exit'], [0])
                    self.assertFalse(any(item['kind'] == 'exception' and not item['first_chance'] for item in events))
                    self.assertEqual(json.loads(marker.read_text()), {'threads': 8, 'lookups': 1024, 'calls': 2048})
                    providers = [item for item in events if item['kind'] == 'provider']
                    if profile == 'loader':
                        lookups = [item['data'] for item in providers if item['data'].get('name') == '__wine_dbg_get_channel_flags']
                        self.assertGreaterEqual(len(lookups), 1024)
                        self.assertTrue(all(item['success'] and int(item['address'], 16) for item in lookups))
                    else:
                        self.assertEqual(providers, [])

    def test_stderr_tail_survives_real_x86_and_x64_targets(self):
        tail = b'\neagle stderr tail\xff\x00\n'
        for bits in (32, 64):
            with self.subTest(bits=bits):
                process, root = self.launch(f'stderr-{bits}', f'target{bits}.exe', 'stderr')
                self.assertEqual(process.wait(timeout=40), 0)
                manifest, events = read_bundle(root)
                self.assertTrue(manifest['completed'])
                self.assertEqual(manifest['dropped_events'], 0)
                self.assertEqual([item['code'] for item in events if item['kind'] == 'process_exit'], [0])
                data = (root / 'stderr.log').read_bytes()
                self.assertEqual(len(data), 1024 * 1024)
                self.assertTrue(data.endswith(tail))
                self.assertGreaterEqual(manifest['stderr_bytes'], 300 * 4096 + len(tail))
                self.assertEqual(manifest['discarded_stderr_bytes'], manifest['stderr_bytes'] - len(data))
                self.assertEqual(manifest['stderr_capture']['retained_bytes'], len(data))
                self.assertEqual(manifest['stderr_capture']['sha256'], hashlib.sha256(data).hexdigest())
                destination = ROOT / f'stderr-{bits}-export.log'
                subprocess.run([str(CLI), 'export', str(root), str(destination)], check=True, stdout=subprocess.DEVNULL)
                self.assertNotIn('eagle stderr tail', destination.read_text())

    def test_parent_exit_does_not_drop_child(self):
        process, root = self.launch("child-tree", argument="child")
        self.assertEqual(process.wait(timeout=40), 0)
        _, events = read_bundle(root)
        self.assertEqual(sum(item["kind"] == "process_create" for item in events), 2)
        self.assertEqual(sorted(item["code"] for item in events if item["kind"] == "process_exit"), [0, 7])

    def test_window_start_does_not_capture_desktop_bootstrap(self):
        env = dict(os.environ, WINEPREFIX=str(ROOT / "prefix"))
        server = Path(WINE).parent / "wineserver"
        for bits in (64, 32):
            subprocess.run([str(server), "-k"], env=env, check=False)
            subprocess.run([str(server), "-w"], env=env, check=True, timeout=30)
            process, root = self.launch(f"desktop-{bits}", f"target{bits}.exe", "window", timeout=120)
            self.assertEqual(process.wait(timeout=130), 0)
            manifest, events = read_bundle(root)
            self.assertTrue(manifest["completed"])
            self.assertEqual(sum(item["kind"] == "process_create" for item in events), 1)
            self.assertEqual([item["code"] for item in events if item["kind"] == "process_exit"], [0])

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

    def test_register_snapshot_retains_arguments_and_index_registers(self):
        for bits in (64, 32):
            process, root = self.launch(f"registers-{bits}", f"target{bits}.exe", "registers", interactive=True)
            initial = self.wait_event(root, "stopped")
            send_command(root, "break eagle_register_arguments")
            self.wait_event(root, "breakpoint_set")
            send_command(root, "continue")
            stopped = self.wait_event(root, "stopped", initial["seq"])
            self.assertEqual(stopped["reason"], "breakpoint")
            send_command(root, "snapshot")
            stack = self.wait_event(root, "snapshot", stopped["seq"])
            self.assertEqual(stack["frames"][0]["symbol"], "eagle_register_arguments")
            registers = stack["registers"]
            expected = {"ip", "sp", "bp", "ax", "bx", "cx", "dx", "si", "di", "flags"}
            if bits == 64:
                expected.update(f"r{number}" for number in range(8, 16))
                self.assertEqual(registers["cx"], "0x11")
                self.assertEqual(registers["dx"], "0x22")
                self.assertEqual(registers["r8"], "0x8877665544332211")
                self.assertEqual(registers["r9"], "0x123456789abcdef0")
            self.assertEqual(set(registers), expected)
            self.assertTrue(all(isinstance(value, str) and value.startswith("0x")
                                for name, value in registers.items() if name != "flags"))
            send_command(root, "continue")
            self.assertEqual(process.wait(timeout=40), 0)
            manifest, events = read_bundle(root)
            self.assertTrue(manifest["completed"])
            self.assertEqual(next(item for item in events if item["kind"] == "process_exit")["code"], 0)

    def test_pause_without_interactive_mode(self):
        for bits in (64, 32):
            marker = ROOT / f'pause-auto-{bits}.marker'
            process, root = self.launch(f'pause-auto-{bits}', f'target{bits}.exe',
                                       ['tracewait', windows_path(marker)], timeout=60)
            self.wait_event(root, 'process_create')
            send_command(root, 'pause')
            paused = self.wait_event(root, 'stopped')
            self.assertEqual(paused['reason'], 'pause')
            send_command(root, 'snapshot')
            self.wait_event(root, 'snapshot_complete', paused['seq'])
            time.sleep(9)
            self.assertFalse(marker.exists())
            self.assertIsNone(process.poll())
            send_command(root, 'continue')
            self.assertEqual(process.wait(timeout=70), 0)
            manifest, events = read_bundle(root)
            self.assertTrue(manifest['completed'])
            self.assertEqual(marker.read_bytes(), b'alive')
            self.assertEqual(next(item['code'] for item in events if item['kind'] == 'process_exit'), 0)
            self.assertFalse([item for item in events if item['kind'] == 'error'])

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
        stack = request(5, "stackTrace", {"threadId": tid, "levels": 0})
        self.assertEqual(stack["stackFrames"][0]["name"], "eagle_checkpoint")
        self.assertGreaterEqual(stack["totalFrames"], 4)
        scopes = request(6, "scopes", {"frameId": stack["stackFrames"][0]["id"]})
        registers = request(7, "variables", {"variablesReference": scopes["scopes"][0]["variablesReference"]})
        values = {item["name"]: item["value"] for item in registers["variables"]}
        self.assertTrue({"si", "di"} | {f"r{i}" for i in range(8, 16)} <= values.keys())
        self.assertEqual(values["cx"], "0x5")
        request(8, "continue", {"threadId": tid})
        while read_message(process.stdout).get("event") != "terminated":
            pass
        request(9, "disconnect")
        process.stdin.close()
        self.assertEqual(process.wait(timeout=15), 0)
        process.stdout.close()

    def test_dap_child_exits_do_not_replace_the_main_exit(self):
        for bits, architecture in ((32, "x86"), (64, "x86_64")):
            for mode in ("childjoin", "childwait"):
                with self.subTest(bits=bits, mode=mode):
                    bundle = ROOT / f"dap-{mode}-{bits}"
                    process = subprocess.Popen([str(CLI), "dap"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    self.addCleanup(lambda process=process: process.poll() is None and process.terminate())
                    messages = []
                    output = (ROOT / f"dap-{mode}-{bits}.log").open("w")
                    self.addCleanup(output.close)
                    seq = 0
                    def receive():
                        message = read_message(process.stdout)
                        self.assertIsNotNone(message)
                        messages.append(message)
                        output.write(json.dumps(message) + "\n"); output.flush()
                        return message
                    def request(command, arguments=None):
                        nonlocal seq
                        seq += 1
                        write_message(process.stdin, {"seq": seq, "type": "request", "command": command, "arguments": arguments or {}})
                        while True:
                            message = receive()
                            if message["type"] == "response" and message["request_seq"] == seq:
                                self.assertTrue(message["success"], message)
                                return message["body"]
                    request("initialize")
                    request("launch", {"wine": WINE, "prefix": str(ROOT / "prefix"), "session": str(bundle),
                                       "program": str(ROOT / f"target{bits}.exe"), "args": [mode], "architecture": architecture})
                    if mode == "childjoin":
                        self.assertTrue(request("setFunctionBreakpoints", {"breakpoints": [{"name": "eagle_checkpoint"}]})["breakpoints"][0]["verified"])
                    pending = len(messages)
                    request("configurationDone")
                    checkpoint = False
                    while True:
                        message = messages[pending] if pending < len(messages) else receive()
                        pending += 1
                        if message.get("event") == "terminated": break
                        if message.get("event") == "stopped":
                            if message["body"]["reason"] == "breakpoint":
                                self.assertEqual(mode, "childjoin")
                                self.assertFalse(any(item.get("event") == "exited" for item in messages))
                                self.assertEqual(self.wait_event(bundle, "process_exit")["code"], 7)
                                checkpoint = True
                            request("continue", {"threadId": message["body"]["threadId"]})
                    self.assertEqual(checkpoint, mode == "childjoin")
                    self.assertEqual([item["body"]["exitCode"] for item in messages if item.get("event") == "exited"], [0])
                    manifest, events = read_bundle(bundle)
                    self.assertTrue(manifest["completed"])
                    self.assertEqual(manifest["dropped_events"], 0)
                    created = [item["pid"] for item in events if item["kind"] == "process_create"]
                    exited = [(item["pid"], item["code"]) for item in events if item["kind"] == "process_exit"]
                    self.assertEqual(len(created), 2)
                    self.assertEqual(exited, [(created[1], 7), (created[0], 0)] if mode == "childjoin" else [(created[0], 0), (created[1], 7)])
                    request("disconnect")
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

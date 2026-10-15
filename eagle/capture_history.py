import collections
import json

PREFIX_BYTES = 64 * 1024 * 1024
RECENT_BYTES = 4 * 1024 * 1024
TERMINAL_BYTES = 4 * 1024 * 1024
PREFIX_EVENTS = 1000000
RECENT_EVENTS = 4096
TERMINAL_EVENTS = 128


class CaptureHistory:
    def __init__(self, output, manifest, bounded):
        self.output, self.manifest, self.bounded = output, manifest, bounded
        self.count = self.bytes = self.prefix_count = self.prefix_bytes = 0
        self.prefix_seq = None
        self.prefix_open = True
        self.recent, self.terminal = collections.deque(), collections.deque()
        self.recent_bytes = self.terminal_bytes = 0
        self.root_pid = self.exit_code = None

    def __enter__(self):
        return self

    def write(self, event):
        index = self.count
        self.count += 1
        if not self.bounded and self.count > PREFIX_EVENTS:
            self.manifest['dropped_events'] += 1
            return False
        line = json.dumps(event) + '\n'
        start = self.bytes
        self.bytes += len(line)
        if not self.bounded:
            self.output.write(line)
            self.output.flush()
            return True
        if event['kind'] == 'process_create' and self.root_pid is None:
            self.root_pid = event['pid']
        if event['kind'] == 'process_exit' and self.root_pid is not None and event['pid'] == self.root_pid and self.exit_code is None:
            self.exit_code = event['code']
        if self.prefix_open and self.count <= PREFIX_EVENTS and self.prefix_bytes + len(line) <= PREFIX_BYTES:
            self.output.write(line)
            self.output.flush()
            self.prefix_count += 1
            self.prefix_bytes += len(line)
            self.prefix_seq = event.get('seq')
            return True
        self.prefix_open = False
        entry = (index, start, self.bytes, event.get('seq'), line)
        self.recent.append(entry)
        self.recent_bytes += len(line)
        while self.recent and (self.recent_bytes > RECENT_BYTES or len(self.recent) > RECENT_EVENTS):
            self.recent_bytes -= len(self.recent.popleft()[4])
        if event['kind'] == 'exception' and event.get('first_chance') is False:
            self.terminal.append(entry)
            self.terminal_bytes += len(line)
            while self.terminal and (self.terminal_bytes > TERMINAL_BYTES or len(self.terminal) > TERMINAL_EVENTS):
                self.terminal_bytes -= len(self.terminal.popleft()[4])
        return False

    def __exit__(self, kind, value, traceback):
        if not self.bounded:
            return
        retained = {entry[0]: entry for entry in (*self.terminal, *self.recent)}
        previous, end, seq = self.prefix_count - 1, self.prefix_bytes, self.prefix_seq
        gap_count = gap_bytes = retained_bytes = 0
        for index, start, finish, next_seq, line in sorted(retained.values()):
            if index > previous + 1:
                gap = dict(kind='capture_gap', omitted_events=index - previous - 1, omitted_bytes=start - end)
                if type(seq) is int and type(next_seq) is int and 0 <= seq < next_seq - 1 <= 0xffffffffffffffff:
                    gap.update(seq=seq + 1, sequence_origin='synthetic gap boundary')
                encoded = json.dumps(gap) + '\n'
                self.output.write(encoded)
                gap_count += 1
                gap_bytes += len(encoded)
            self.output.write(line)
            retained_bytes += len(line)
            previous, end, seq = index, finish, next_seq
        if self.count > previous + 1:
            gap = dict(kind='capture_gap', omitted_events=self.count - previous - 1, omitted_bytes=self.bytes - end)
            encoded = json.dumps(gap) + '\n'
            self.output.write(encoded)
            gap_count += 1
            gap_bytes += len(encoded)
        self.output.flush()
        omitted = self.count - self.prefix_count - len(retained)
        self.manifest['dropped_events'] += omitted
        self.manifest['capture_history'] = dict(coverage='partial' if omitted else 'complete',
            observed_events=self.count, retained_events=self.count - omitted, omitted_bytes=self.bytes - self.prefix_bytes - retained_bytes,
            prefix_byte_limit=PREFIX_BYTES, recent_byte_limit=RECENT_BYTES, terminal_byte_limit=TERMINAL_BYTES,
            prefix_event_limit=PREFIX_EVENTS, recent_event_limit=RECENT_EVENTS, terminal_event_limit=TERMINAL_EVENTS,
            event_bytes=self.prefix_bytes + retained_bytes, gap_records=gap_count, gap_bytes=gap_bytes)
        self.manifest['capture_root'] = dict(pid=self.root_pid, exit_code=self.exit_code)
        self.recent.clear()
        self.terminal.clear()

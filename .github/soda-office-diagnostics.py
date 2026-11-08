from collections import deque
import json
import math
from pathlib import Path
import re
import sys


FILE_LIMIT = 32
BYTE_LIMIT = 16 * 1024 * 1024
EVENT_LIMIT = 300


def office_version(prefix):
    path = prefix / 'system.reg'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        return None
    section = False
    with path.open(errors='replace') as file:
        for line in file:
            if line.startswith('['):
                key = line.split(']', 1)[0][1:].replace('\\\\', '\\')
                section = key.casefold() == r'Software\Microsoft\Office\ClickToRun\Configuration'.casefold()
            elif section:
                match = re.fullmatch(r'"VersionToReport"="([0-9]{1,5}(?:\.[0-9]{1,5}){3})"\s*', line)
                if match:
                    return match[1]
    return None


def event_metadata(line):
    fields = line.rstrip('\r\n\0').split('\t', 8)
    if len(fields) < 8:
        return None
    category, event_id, level, message = fields[4:8]
    if not re.fullmatch(r'[A-Za-z0-9]{1,16}', event_id):
        return None
    row = {}
    if category in ('Word Font', 'Word Print', 'DWA Font Collection'):
        row.update(category=category, event_id=event_id)
        if level in ('Verbose', 'Medium', 'Unexpected', 'High', 'Monitorable', 'Info'):
            row['level'] = level
    start = message.find('{')
    if start >= 0:
        try:
            data = json.loads(message[start:])
        except ValueError:
            data = None
        name = data.get('EventName', data.get('Name', '')) if isinstance(data, dict) else ''
        if re.fullmatch(r'Office\.[A-Za-z0-9_.]{1,180}', str(name)):
            row['activity'] = name
            activity = data.get('Activity', data)
            if isinstance(activity, dict):
                for key in ('Duration', 'Count', 'Success', 'AggMode'):
                    value = activity.get(key)
                    if key == 'Success' and type(value) is bool:
                        row[key] = value
                    elif key != 'Success' and type(value) in (int, float) and 0 <= value <= 10**16 and math.isfinite(value):
                        row[key] = value
                outcome = activity.get('Result')
                if isinstance(outcome, dict) and type(outcome.get('Code')) is int:
                    row['result_code'] = outcome['Code']
                if type(activity.get('Result.Code')) is int:
                    row['result_code'] = activity['Result.Code']
                if type(activity.get('Data.ErrorCode')) is int:
                    row['error_code'] = activity['Data.ErrorCode']
            details = data.get('Data')
            if isinstance(details, dict) and type(details.get('ErrorCode')) is int:
                row['error_code'] = details['ErrorCode']
    return row or None


def collect(prefix, since=0):
    prefix = prefix.resolve(strict=True)
    paths = []
    for temp in (prefix / 'drive_c/users').glob('*/AppData/Local/Temp'):
        if not temp.resolve().is_relative_to(prefix):
            continue
        for pattern in ('*.log', 'Diagnostics/WINWORD/*.log', 'Diagnostics/AI/*.log'):
            for path in temp.glob(pattern):
                if not path.is_symlink() and path.resolve().is_relative_to(prefix) and path.is_file() and path.stat().st_mtime >= since:
                    paths.append(path)
    paths = sorted(set(paths), key=lambda path: path.stat().st_mtime)
    events = deque(maxlen=EVENT_LIMIT)
    result = {'schema': 1, 'office_version': office_version(prefix), 'files_considered': len(paths),
              'files_omitted': max(0, len(paths) - FILE_LIMIT), 'files_truncated': 0,
              'events_omitted': 0, 'scope': 'Bounded Office activity/category metadata and numeric failure codes; free-form messages, correlation, user and path fields omitted'}
    for path in paths[-FILE_LIMIT:]:
        with path.open('rb') as file:
            raw = file.read(BYTE_LIMIT + 1)
        result['files_truncated'] += len(raw) > BYTE_LIMIT
        raw = raw[:BYTE_LIMIT]
        text = raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8', errors='replace')
        for line in text.rstrip('\0').splitlines():
            row = event_metadata(line)
            if row:
                result['events_omitted'] += len(events) == EVENT_LIMIT
                events.append(row)
    result['events'] = list(events)
    return result


WAIT_BYTE_LIMIT = 16 * 1024 * 1024
WAIT_EVENT_LIMIT = 2048


def wait_context(session, report):
    faults = {}
    for event in report.get('terminal_exceptions', []):
        values = tuple(event.get(key) for key in ('pid', 'tid', 'time_ms'))
        if all(type(value) is int and 0 <= value < 2**64 for value in values):
            key = values[:2]
            faults[key] = min(faults.get(key, values[2]), values[2])
    assert len(faults) <= 16, 'Too many fault threads for bounded context'
    rows = {key: deque(maxlen=WAIT_EVENT_LIMIT) for key in faults}
    counts = dict.fromkeys(faults, 0)
    unmatched = dict.fromkeys(faults)
    malformed = 0
    with (Path(session) / 'events.jsonl').open('rb') as file:
        raw = file.read(WAIT_BYTE_LIMIT + 1)
    truncated = len(raw) > WAIT_BYTE_LIMIT
    lines = raw[:WAIT_BYTE_LIMIT].splitlines()
    if truncated:
        lines = lines[:-1]
    for line in lines:
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            malformed += 1
            continue
        if not isinstance(event, dict):
            malformed += 1
            continue
        values = tuple(event.get(key) for key in ('pid', 'tid', 'time_ms', 'seq'))
        if not all(type(value) is int and 0 <= value < 2**64 for value in values):
            continue
        key, stamp = values[:2], values[2]
        if key not in faults or stamp > faults[key]:
            continue
        data = event.get('data')
        if event.get('kind') != 'provider' or not isinstance(data, dict) or data.get('provider') != 8:
            continue
        name = data.get('event')
        if name not in ('WaitBegin', 'WaitEnd', 'MutexCreate', 'MutexRelease', 'HandleClose', 'ObserverBudgetExceeded'):
            continue
        row = dict(zip(('pid', 'tid', 'time_ms', 'seq'), values), event=name)
        for field in ('value', 'timeout_ms', 'limit'):
            value = data.get(field)
            if type(value) is int and 0 <= value < 2**64:
                row[field] = value
        value = data.get('object')
        if isinstance(value, str) and re.fullmatch(r'(?:0x)?[0-9a-fA-F]{1,16}', value):
            row['object'] = int(value, 16)
        if name == 'WaitBegin':
            unmatched[key] = row
        elif name == 'WaitEnd':
            unmatched[key] = None
        if stamp < faults[key] - 2000:
            continue
        counts[key] += 1
        rows[key].append(row)
    return {'schema': 1, 'scope': 'Numeric wait events on terminal fault threads in the preceding 2000ms; no raw session fields',
            'bytes_truncated': truncated, 'malformed_rows': malformed,
            'threads': [{'pid': key[0], 'tid': key[1], 'fault_time_ms': faults[key],
                         'events_omitted': counts[key] - len(rows[key]), 'events': list(rows[key]),
                         'last_unmatched_wait_begin_observed': unmatched[key]}
                        for key in faults]}


if __name__ == '__main__':
    if sys.argv[1] == 'wait-context':
        report = json.loads(Path(sys.argv[4]).read_text())
        result = wait_context(Path(sys.argv[2]), report)
        Path(sys.argv[3]).write_text(json.dumps(result, indent=2) + '\n')
    else:
        Path(sys.argv[2]).write_text(json.dumps(collect(Path(sys.argv[1]), float(sys.argv[3])), indent=2) + '\n')

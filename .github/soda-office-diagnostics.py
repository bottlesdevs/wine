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
        if isinstance(data, dict) and re.fullmatch(r'Office\.[A-Za-z0-9_.]{1,180}', str(data.get('EventName', ''))):
            row['activity'] = data['EventName']
            activity = data.get('Activity')
            if isinstance(activity, dict):
                for key in ('Duration', 'Count', 'Success', 'AggMode'):
                    value = activity.get(key)
                    if key == 'Success' and type(value) is bool:
                        row[key] = value
                    elif key != 'Success' and type(value) in (int, float) and 0 <= value <= 10**16 and math.isfinite(value):
                        row[key] = value
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
              'events_omitted': 0, 'scope': 'Bounded Office activity/category metadata; message, Data, correlation, user and path fields omitted'}
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


if __name__ == '__main__':
    Path(sys.argv[2]).write_text(json.dumps(collect(Path(sys.argv[1]), float(sys.argv[3])), indent=2) + '\n')

import json
import os
import stat
import collections

from session import summarize, validate_event, validate_manifest

MAX_REPORT = 32 * 1024 * 1024
EVENT_LISTS = ('timeline', 'snapshots', 'terminal_exceptions', 'providers', 'observed_wait_cycles', 'dumps')
DUMP_FIELDS = ('seq', 'time_ms', 'kind', 'pid', 'tid', 'path', 'size')
EXPORT_LISTS = ('terminal_exceptions', 'exits', 'observed_wait_cycles', 'timeline', 'dumps', 'providers', 'snapshots')


def export_omissions(report):
    metadata = report.get('export', {})
    if not isinstance(metadata, dict):
        raise ValueError('invalid export metadata')
    if not {'summary_limit_bytes', 'omitted_records'} & set(metadata):
        return {}
    limit, omitted = metadata.get('summary_limit_bytes'), metadata.get('omitted_records')
    if type(limit) is not int or not 0 < limit <= MAX_REPORT or not isinstance(omitted, dict):
        raise ValueError('invalid export summary limit')
    if set(omitted) - set(EXPORT_LISTS) or any(type(value) is not int or value < 0 for value in omitted.values()):
        raise ValueError('invalid export omission counts')
    return dict(omitted)

def bound_export(report):
    size = 1
    for piece in json.JSONEncoder(indent=2).iterencode(report):
        size += len(piece)
        if size > MAX_REPORT:
            break
    else:
        return report
    previous = export_omissions(report)
    records = {name: report.get(name, []) for name in EXPORT_LISTS}
    limited = dict(report, **{name: [] for name in EXPORT_LISTS})
    omitted = {name: previous.get(name, 0) + len(values) for name, values in records.items()}
    limited['export'] = dict(report['export'], summary_limit_bytes=MAX_REPORT, omitted_records=omitted)
    if 'input_coverage' in limited:
        limited['input_coverage'] = dict(limited['input_coverage'], export_omitted_records=omitted)
    remaining = MAX_REPORT - len(json.dumps(limited, indent=2)) - 1
    if remaining < 0:
        raise ValueError('session report metadata exceeds export size limit')
    indices = {name: list(range(len(values))) for name, values in records.items()}
    groups = collections.defaultdict(list)
    for index, event in enumerate(records['providers']):
        groups[event.get('data', {}).get('provider')].append(index)
    provider_order = []
    while groups:
        for provider in list(groups):
            provider_order.append(groups[provider].pop())
            if not groups[provider]:
                del groups[provider]
    indices['providers'] = provider_order[::-1]
    pending = {name: values for name, values in indices.items() if values}
    selected = {name: [] for name in records}
    while pending:
        for name in list(pending):
            index = pending[name].pop()
            event = records[name][index]
            encoded = json.dumps(event, indent=2)
            cost = len(encoded) + 4 * (encoded.count('\n') + 1) + 8
            if cost > remaining:
                del pending[name]
                continue
            selected[name].append((index, event))
            remaining -= cost
            omitted[name] -= 1
            if not pending[name]:
                del pending[name]
    for name, values in selected.items():
        limited[name] = [event for index, event in sorted(values)]
    return limited


def load_report(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as file:
        information = os.fstat(file.fileno())
        if not stat.S_ISREG(information.st_mode):
            raise ValueError('session report must be a regular file')
        if information.st_size > MAX_REPORT:
            raise ValueError('session report exceeds 32 MiB limit')
        data = file.read(MAX_REPORT + 1)
    if len(data) > MAX_REPORT:
        raise ValueError('session report exceeds 32 MiB limit')
    first = data.split(b'\n', 1)[0]
    try:
        header = json.loads(first)
    except ValueError:
        header = None
    if isinstance(header, dict) and header.get('format') == 'eagle-live-v1':
        return live_report(data, header)
    if isinstance(header, dict) and isinstance(header.get('format'), str) and header['format'].startswith('eagle-live-'):
        raise ValueError('unsupported live session format')
    return exported_report(json.loads(data))

def live_report(data, header):
    limit = header.get('byte_limit')
    if limit is not None and (type(limit) is not int or limit <= 0):
        raise ValueError('invalid live session byte limit')
    events = []
    lines = data.splitlines()[1:]
    incomplete = False
    for index, line in enumerate(lines):
        if len(line) > 2 * 1024 * 1024:
            raise ValueError('session event exceeds size limit')
        try:
            event = json.loads(line)
        except ValueError:
            if index == len(lines) - 1 and not data.endswith(b'\n'):
                incomplete = True
                break
            raise ValueError('invalid live session event at line ' + str(index + 2))
        validate_event(event, 'invalid live session event at line ' + str(index + 2))
        events.append(event)
    manifest = dict(schema=1, completed=False, input_format='eagle-live-v1')
    report = summarize(manifest, events)
    report['input_coverage'] = dict(format='eagle-live-v1', history='live partial', event_order='stream',
                                    retained_records=len(events), incomplete_tail=incomplete, declared_byte_limit=limit,
                                    capture_limited=any(event['kind'] == 'capture_limit' for event in events))
    return report, events

def exported_report(report):
    allowed = {'manifest', 'counts', 'exits', 'terminal_exceptions', 'snapshots', 'dumps', 'providers', 'provider_selection',
               'timeline', 'timeline_events_omitted', 'provider_events_omitted', 'observed_wait_cycles', 'wait_cycles_omitted',
               'offline_symbolization', 'export', 'input_coverage'}
    if not isinstance(report, dict) or set(report) - allowed or 'manifest' not in report or 'counts' not in report:
        raise ValueError('not a supported Eagle session report')
    validate_manifest(report['manifest'])
    omitted = export_omissions(report)
    counts = report['counts']
    if not isinstance(counts, dict) or any(type(value) is not int or value < 0 for value in counts.values()):
        raise ValueError('invalid exported event counts')
    for name in ('timeline_events_omitted', 'provider_events_omitted', 'wait_cycles_omitted'):
        if report.get(name) is not None and (type(report[name]) is not int or report[name] < 0):
            raise ValueError('invalid exported omission count')
    if not isinstance(report.get('exits', []), list):
        raise ValueError('invalid exported process exits')
    expected = dict(snapshots='snapshot', terminal_exceptions='exception', providers='provider', observed_wait_cycles='provider', dumps='dump')
    records = []
    memory_excluded = 0
    for name in EVENT_LISTS:
        values = report.get(name, [])
        if not isinstance(values, list):
            raise ValueError('invalid exported event list: ' + name)
        retained = []
        for index, event in enumerate(values):
            validate_event(event, 'invalid exported ' + name + ' record ' + str(index))
            if name in expected and event['kind'] != expected[name]:
                raise ValueError('unexpected event in exported ' + name)
            if name == 'terminal_exceptions' and event['first_chance']:
                raise ValueError('first-chance event in terminal exceptions')
            if event['kind'] == 'memory':
                memory_excluded += 1
                continue
            if event['kind'] == 'dump':
                event = {key: event[key] for key in DUMP_FIELDS if key in event}
            retained.append(event)
            records.append(event)
        report[name] = retained
    ordered = all(type(event.get('seq')) is int and event['seq'] >= 0 for event in records)
    unique = {}
    if ordered:
        for event in records:
            key = event['seq']
            if key in unique and unique[key] != event:
                raise ValueError('conflicting exported event sequence')
            unique.setdefault(key, event)
        for name in EVENT_LISTS:
            report[name] = [unique[event['seq']] for event in report[name]]
        records = [unique[key] for key in sorted(unique)]
    report['input_coverage'] = dict(format='exported-summary', history='retained subset',
                                    event_order='sequence' if ordered else 'unverified', retained_records=len(records),
                                    memory_records_excluded=memory_excluded,
                                    timeline_omitted=report.get('timeline_events_omitted'), providers_omitted=report.get('provider_events_omitted'))
    if omitted:
        report['input_coverage']['export_omitted_records'] = omitted
    return report, records

import collections
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from dwarf import file_identity, file_state
from symbols import image_metadata, query


def read_images(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError('symbol image selection must be a regular file')
        data = file.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('symbol image selection exceeds limit')
    return json.loads(data)

def image_maps(values):
    if not isinstance(values, list) or len(values) > 256:
        raise ValueError('symbol_images must contain at most 256 reviewed images')
    result = {}
    for value in values:
        if not isinstance(value, dict) or set(value) - {'sha256', 'image', 'pdb', 'debug_files', 'inlines'}:
            raise ValueError('invalid reviewed symbol image')
        digest = value.get('sha256')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-fA-F]{64}', digest):
            raise ValueError('reviewed symbol image requires SHA256')
        for key in ('image', 'pdb'):
            if (key == 'image' or key in value) and (not isinstance(value.get(key), str) or not value[key] or len(value[key]) > 4096):
                raise ValueError('invalid reviewed image or PDB path')
        files = value.get('debug_files', [])
        if not isinstance(files, list) or len(files) > 256 or any(not isinstance(path, str) or not path or len(path) > 4096 for path in files):
            raise ValueError('invalid reviewed debug files')
        if type(value.get('inlines', True)) is not bool:
            raise ValueError('reviewed image inlines must be boolean')
        digest = digest.lower()
        value = dict(value, sha256=digest)
        if digest in result and result[digest] != value:
            raise ValueError('ambiguous reviewed images for SHA256')
        result[digest] = value
    return result

def path_key(path):
    if not isinstance(path, str) or not path:
        return None
    if '\\' in path or re.match('^[A-Za-z]:', path):
        return re.sub(r'[\\/]+', '/', path.removeprefix('\\\\?\\')).casefold()
    return path

def number(value):
    if type(value) not in (str, int):
        raise ValueError('recorded address is missing')
    result = int(value, 0) if isinstance(value, str) else value
    if not 0 <= result <= 0xffffffffffffffff:
        raise ValueError('recorded address is invalid')
    return result

def recorded_frames(manifest, events, ordered=True):
    if not ordered:
        for event in events:
            for frame in ([event['frame']] if event.get('frame') is not None else []) + event.get('frames', []):
                yield event, frame, None, None, None, 'retained event order is unavailable'
        return
    active = {}
    names = collections.defaultdict(dict)
    timeline = any(event['kind'] in ('process_create', 'module_load', 'module_unload') for event in events)
    inventory = {path_key(path): value for path, value in manifest.get('modules', {}).items()}
    ended = set()
    def remove(pid, base=None):
        for key in list(active):
            if key[0] != pid or (base is not None and key[1] != base):
                continue
            record = active.pop(key)
            for alias in record['aliases']:
                names[(pid, alias)].pop(key[1], None)
                if not names[(pid, alias)]:
                    del names[(pid, alias)]
    for event in events:
        pid = event.get('pid')
        kind = event['kind']
        if type(pid) is not int or pid <= 0:
            for frame in ([event['frame']] if event.get('frame') is not None else []) + event.get('frames', []):
                yield event, frame, None, None, None, 'recorded process identity is unavailable'
            continue
        if kind == 'process_create':
            remove(pid)
            ended.discard(pid)
        if kind in ('process_create', 'module_load'):
            try:
                if type(pid) is not int or pid <= 0:
                    raise ValueError('invalid recorded process')
                base = number(event.get('base'))
                remove(pid, base)
                aliases = {path_key(event.get(key)) for key in ('path', 'image')} - {None}
                record = dict(identity=event.get('identity', {}), origin=event.get('identity_origin', 'not recorded'), aliases=aliases)
                active[(pid, base)] = record
                for alias in aliases:
                    names[(pid, alias)][base] = record
            except ValueError:
                remove(pid)
        elif kind == 'module_unload':
            try:
                remove(pid, number(event.get('base')))
            except ValueError:
                remove(pid)
        elif kind == 'process_exit':
            remove(pid)
            ended.add(pid)
        frames = ([event['frame']] if event.get('frame') is not None else []) + event.get('frames', [])
        for frame in frames:
            try:
                rva = number(frame.get('rva'))
                image = path_key(frame.get('image'))
                if image is None:
                    raise ValueError('recorded frame image is missing')
                candidates = names.get((pid, image), {})
                if 'address' in frame:
                    base = number(frame['address']) - rva
                    record = candidates.get(base)
                else:
                    record = next(iter(candidates.values())) if len(candidates) == 1 and image != '[redacted]' else None
                if record is None and not timeline and pid not in ended and image in inventory:
                    record = dict(identity=inventory[image], origin='manifest only; runtime unverified')
                if record is None:
                    raise ValueError('recorded module identity is missing or ambiguous')
                identity = record['identity']
                digest = identity.get('sha256') if isinstance(identity, dict) else None
                if not isinstance(digest, str) or not re.fullmatch('[0-9a-fA-F]{64}', digest):
                    raise ValueError('recorded module SHA256 is unavailable')
                yield event, frame, digest.lower(), rva, record['origin'], None
            except ValueError as error:
                yield event, frame, None, None, None, str(error)

def enrich(manifest, events, values, ordered=True):
    mappings = image_maps(values)
    deadline = time.monotonic() + 20
    selected = {}
    priority = {level: collections.OrderedDict() for level in (1, 2, 3)}
    for event, frame, digest, rva, origin, reason in recorded_frames(manifest, events, ordered):
        if time.monotonic() >= deadline:
            raise ValueError('saved-frame symbolization timed out')
        annotation = dict(status='unavailable')
        frame['offline_symbols'] = annotation
        if reason:
            annotation['reason'] = reason
            continue
        annotation.update(image_sha256=digest, identity_origin=origin, rva=hex(rva))
        if digest not in mappings:
            annotation['reason'] = 'no reviewed image for recorded SHA256'
            continue
        annotation['reason'] = 'offline address limit reached'
        key = digest, rva
        level = 3 if event['kind'] == 'exception' and not event['first_chance'] else 2 if event['kind'] == 'snapshot' else 1
        if key in selected:
            old = selected[key]
            level = max(level, old)
            del priority[old][key]
        elif len(selected) >= 256:
            lowest = min(value for value, bucket in priority.items() if bucket)
            if level < lowest:
                continue
            previous, _ = priority[lowest].popitem(last=False)
            del selected[previous]
        priority[level][key] = None
        selected[key] = level
    requested = collections.defaultdict(set)
    for digest, rva in selected:
        requested[digest].add(rva)
    cache = {}
    images = {}
    for digest, offsets in requested.items():
        if not offsets:
            continue
        if time.monotonic() >= deadline:
            raise ValueError('saved-frame symbolization timed out')
        selection = mappings[digest]
        image = Path(selection['image'])
        try:
            image = image.resolve(strict=True)
            identity, before = file_identity(image, deadline)
            if identity['sha256'] != digest:
                raise ValueError('selected image SHA256 does not match recorded module')
            size = image_metadata(image)['size']
            addresses = sorted(offset for offset in offsets if offset < size)
            result = query(image, pdb=selection.get('pdb'), rvas=[hex(offset) for offset in addresses],
                           debug_files=selection.get('debug_files') or None, inlines=selection.get('inlines', True))
            if result['sha256'] != digest or before != file_state(image.stat()):
                raise ValueError('selected image changed during saved-frame lookup')
            images[digest] = {key: result[key] for key in ('pdb_identity', 'pdb_matches', 'inline_artifacts', 'inline_debug_image') if key in result}
            images[digest]['image'] = str(image)
            for offset, resolved in zip(addresses, result['resolved']):
                resolved = dict(resolved)
                diagnostic = {key: resolved.pop(key) for key in ('symbol_reason', 'inline_reason') if key in resolved}
                cache[(digest, offset)] = dict(status=resolved['status'], resolved=resolved)
                if diagnostic:
                    cache[(digest, offset)]['offline_diagnostic'] = diagnostic
            for offset in offsets - set(addresses):
                cache[(digest, offset)] = dict(status='unavailable', reason='recorded RVA is outside the selected image')
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            images[digest] = dict(image=str(image), status='unavailable', error_type=type(error).__name__, offline_diagnostic=str(error))
            for offset in offsets:
                cache[(digest, offset)] = dict(status='unavailable', reason='selected image lookup failed', error_type=type(error).__name__)
    counts = collections.Counter()
    for event in events:
        for frame in ([event['frame']] if event.get('frame') is not None else []) + event.get('frames', []):
            if time.monotonic() >= deadline:
                raise ValueError('saved-frame symbolization timed out')
            annotation = frame['offline_symbols']
            key = (annotation.get('image_sha256'), int(annotation['rva'], 0)) if 'rva' in annotation else None
            if key in cache:
                annotation.pop('reason', None)
                annotation.update(cache[key])
            counts[annotation['status']] += 1
    return dict(images=images, counts=dict(counts), maximum_addresses=256,
                address_selection='terminal exceptions, then recent snapshots, then other frames',
                scope='exact recorded file hashes; runtime identity depends on recorded provenance')

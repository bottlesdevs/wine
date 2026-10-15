import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import posixpath
import re
import stat
import time

from dwarf import file_identity, file_state
from provenance import source_fields
from sources import source_identity


def relative_path(value):
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or PureWindowsPath(value).drive or '\\' in value or
            '..' in path.parts or str(path) != value or value == '.'):
        raise ValueError('invalid recorded source path')
    return value


def source_map(value):
    logical, separator, file = value.partition('=')
    label, colon, path = logical.partition(':')
    if not separator or not colon or not file:
        raise ValueError('source map must be LABEL:RELATIVE=FILE')
    return {'source': label, 'path': path, 'file': file}


def validate_maps(maps):
    if not isinstance(maps, list) or len(maps) > 256:
        raise ValueError('source_maps must be a list of at most 256 mappings')
    for mapping in maps:
        if not isinstance(mapping, dict) or set(mapping) != {'source', 'path', 'file'}:
            raise ValueError('invalid source mapping fields')
        if any(not isinstance(value, str) or not value or len(value) > 4096 for value in mapping.values()):
            raise ValueError('invalid source mapping value')
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', mapping['source']):
            raise ValueError('invalid source label')
        relative_path(mapping['path'])


def read_inventory(path, deadline):
    if path.resolve() != path:
        raise ValueError('runner metadata must not use symlinks')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 32 * 1024 * 1024:
            raise ValueError('invalid runner inventory file')
        data = bytearray()
        for block in iter(lambda: file.read(1024 * 1024), b''):
            data.extend(block)
            if len(data) > 32 * 1024 * 1024 or time.monotonic() >= deadline:
                raise ValueError('runner inventory inspection exceeds limit')
    if file_state(before) != file_state(path.stat()) or path.resolve() != path:
        raise ValueError('runner inventory changed during inspection')
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError('runner inventory must be an object')
    return value, hashlib.sha256(data).hexdigest(), file_state(before)


def source_tree(value):
    identity = source_fields(value)
    files, links = value.get('files'), value.get('symlinks', {})
    if not isinstance(files, dict) or not isinstance(links, dict):
        raise ValueError('invalid source tree inventory')
    for path, checksum in files.items():
        relative_path(path)
        if not isinstance(checksum, str) or not re.fullmatch(r'[0-9a-f]{64}', checksum):
            raise ValueError('invalid source file digest')
    for path, target in links.items():
        relative_path(path)
        if not isinstance(target, str) or not target or path in files:
            raise ValueError('invalid source link inventory')
    version = value.get('tree_format')
    if type(version) is not int or version != (2 if links else 1):
        raise ValueError('invalid source tree format')
    payload = {'files': files, 'symlinks': links} if links else files
    actual = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if actual != identity['tree_sha256']:
        raise ValueError('source tree digest does not match inventory')
    return identity


def recorded_file(source, path):
    files, links = source['files'], source.get('symlinks', {})
    seen = set()
    for _ in range(32):
        if path in seen:
            raise ValueError('cyclic recorded source link')
        seen.add(path)
        if path in files:
            return files[path], path
        parts = PurePosixPath(path).parts
        selected = next((('/'.join(parts[:index]), index) for index in range(1, len(parts) + 1)
                         if '/'.join(parts[:index]) in links), None)
        if selected is None:
            return None, path
        prefix, index = selected
        target = links[prefix]
        if PurePosixPath(target).is_absolute() or PureWindowsPath(target).drive or '\\' in target:
            raise ValueError('recorded source link leaves inventory')
        path = posixpath.normpath(str(PurePosixPath(prefix).parent / target / PurePosixPath(*parts[index:])))
        relative_path(path)
    raise ValueError('recorded source link depth exceeds limit')


def inspect_build_sources(image, runner, maps, expected_sha256):
    result = {'scope': 'recorded build inputs; per-module compile usage and authenticity not attested', 'files': []}
    deadline = time.monotonic() + 20
    had_metadata = False
    try:
        root = Path(runner).resolve(strict=True)
        image = Path(image).resolve(strict=True)
        relative = image.relative_to(root).as_posix()
        actual, image_state = file_identity(image, deadline)
        if actual['sha256'] != expected_sha256:
            raise ValueError('image changed during build source query')
        paths = [root / 'share/soda' / name for name in ('build.json', 'files.json', 'sources.json')]
        present = [path.exists() or path.is_symlink() for path in paths]
        had_metadata = any(present)
        if not had_metadata:
            return dict(result, status='unavailable', reason='runner build source metadata is absent')
        if not all(present):
            raise ValueError('runner build source metadata is incomplete')
        loaded = [read_inventory(path, deadline) for path in paths]
        summary, index, inventory = [item[0] for item in loaded]
        if type(summary.get('schema')) is not int or summary['schema'] != 1:
            raise ValueError('invalid runner build schema')
        if loaded[1][1] != summary.get('files_sha256') or loaded[2][1] != summary.get('sources_sha256'):
            raise ValueError('runner inventory digest does not match build manifest')
        record = index.get(relative)
        if not isinstance(record, dict) or record.get('kind') not in ('elf', 'pe') or record.get('sha256') != expected_sha256:
            return dict(result, status='mismatched', reason='queried image does not match recorded runner')
        launcher = index.get('bin/wine')
        if not isinstance(launcher, dict) or launcher.get('kind') != 'elf' or summary.get('wine') != launcher:
            raise ValueError('runner launcher inventory is inconsistent')
        if summary.get('source_status') not in ('recorded', 'unavailable') or inventory.get('status') != summary['source_status']:
            raise ValueError('inconsistent runner source status')
        if summary['source_status'] == 'unavailable':
            return dict(result, status='unavailable', reason='runner has no recorded build source inventory')
        sources, identities = inventory.get('sources'), summary.get('source_identities')
        if not isinstance(sources, dict) or not isinstance(identities, dict) or not sources or set(sources) != set(identities):
            raise ValueError('inconsistent recorded source identities')
        for label, source in sources.items():
            if source_tree(source) != source_fields(identities[label]):
                raise ValueError('recorded source identity does not match build manifest')
            if time.monotonic() >= deadline:
                raise ValueError('build source inspection timed out')
        result.update(component=summary.get('component'), image={'path': relative, 'sha256': expected_sha256},
                      inventories={'files_sha256': loaded[1][1], 'sources_sha256': loaded[2][1]},
                      sources=[dict(label=label, **source_fields(value)) for label, value in sorted(sources.items())])
        for mapping in maps:
            if time.monotonic() >= deadline:
                raise ValueError('build source inspection timed out')
            item = dict(mapping)
            try:
                source = sources.get(mapping['source'])
                expected, recorded = recorded_file(source, mapping['path']) if source else (None, mapping['path'])
                if expected is None:
                    item['status'] = 'not-recorded'
                else:
                    observed = source_identity(Path(mapping['file']), deadline)
                    item.update(status='matched' if observed['sha256'] == expected else 'mismatched',
                                recorded_path=recorded, expected_sha256=expected, sha256=observed['sha256'])
            except FileNotFoundError:
                item['status'] = 'missing'
            except (OSError, ValueError) as error:
                item.update(status='invalid', reason=str(error))
            result['files'].append(item)
        if image_state != file_state(image.stat()) or any(state != file_state(path.stat()) for path, (_, _, state) in zip(paths, loaded)):
            raise ValueError('build inputs changed during source inspection')
        if len(json.dumps(result).encode()) > 512 * 1024:
            raise ValueError('build source report exceeds limit')
        result['status'] = 'available'
    except FileNotFoundError:
        result.update(status='invalid' if had_metadata else 'unavailable', reason='runner build source metadata is missing', files=[])
    except (OSError, ValueError, KeyError, TypeError) as error:
        result.update(status='invalid', reason=str(error), files=[])
    return result

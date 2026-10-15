import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
import zlib


def dump(tool, path, deadline, arguments=None, output_limit=1024 * 1024, line_filter=None, input_limit=None):
    arguments = arguments if arguments is not None else ['--debug-info', '--recurse-depth=0', '--debug-cu-index']
    process = subprocess.Popen([tool, *arguments, '--', str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=dict(os.environ, LC_ALL='C'))
    output = bytearray()
    pending = b''
    received = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError('split-DWARF inspection timed out')
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    break
                received += len(block)
                if received > (input_limit or output_limit):
                    raise ValueError('split-DWARF tool output exceeds limit')
                if line_filter is None:
                    output.extend(block)
                else:
                    lines = (pending + block).split(b'\n')
                    pending = lines.pop()
                    if len(pending) > 65536:
                        raise ValueError('DWARF tool line exceeds limit')
                    for line in lines:
                        if line_filter(line):
                            output.extend(line + b'\n')
                if len(output) > output_limit:
                    raise ValueError('split-DWARF tool output exceeds limit')
        if process.wait(timeout=max(0.01, deadline - time.monotonic())):
            raise ValueError('split-DWARF tool failed')
        if pending and line_filter is not None and line_filter(pending):
            output.extend(pending)
        if len(output) > output_limit:
            raise ValueError('split-DWARF tool output exceeds limit')
        return output.decode('utf-8', errors='replace')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()

def unit_id(value):
    return '0x' + format(int(value, 16), '016x')

def file_state(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def file_identity(path, deadline):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('debug companion must be a regular file')
    except BaseException:
        os.close(descriptor)
        raise
    digest = hashlib.sha256()
    crc = 0
    with os.fdopen(descriptor, 'rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            if time.monotonic() >= deadline:
                raise ValueError('split-DWARF inspection timed out')
            digest.update(block)
            crc = zlib.crc32(block, crc)
    if file_state(before) != file_state(path.stat()):
        raise ValueError('debug companion changed during inspection')
    return {'sha256': digest.hexdigest(), 'crc32': crc}, file_state(before)

def references(text, limit=256):
    units = []
    for entry in re.split(r'(?m)^0x[0-9a-fA-F]+: Compile Unit:', text)[1:]:
        name = re.search(r'DW_AT_(?:GNU_)?dwo_name\s+\((".*")\)', entry)
        if not name:
            continue
        identifier = re.search(r'(?:DWO_id\s*=\s*|DW_AT_GNU_dwo_id\s+\()(0x[0-9a-fA-F]+)', entry)
        directory = re.search(r'DW_AT_comp_dir\s+\((".*")\)', entry)
        if not identifier:
            raise ValueError('split unit has no DWO identity')
        units.append({'dwo_id': unit_id(identifier[1]), 'name': json.loads(name[1]),
                      'directory': json.loads(directory[1]) if directory else ''})
        if len(units) > limit:
            raise ValueError('split-DWARF unit count exceeds limit')
    return units

def companion(tool, path, deadline, output_limit=1024 * 1024):
    result = {'path': str(path)}
    try:
        identity, before = file_identity(path, deadline)
        result.update(identity)
        text = dump(tool, path, deadline) if output_limit == 1024 * 1024 else dump(tool, path, deadline, output_limit=output_limit)
        split_info = text.partition('.debug_info.dwo contents:')[2]
        ids = re.findall(r'(?:DWO_id\s*=\s*|DW_AT_GNU_dwo_id\s+\()(0x[0-9a-fA-F]+)', split_info)
        ids += re.findall(r'(?m)^\s+[0-9]+\s+(0x[0-9a-fA-F]+)\s+\[', text)
        if before != file_state(path.stat()):
            raise ValueError('debug companion changed during inspection')
        result['dwo_ids'] = sorted({unit_id(value) for value in ids})
        result['status'] = 'available' if ids else 'invalid'
    except FileNotFoundError:
        result['status'] = 'missing'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result.update(status='invalid', reason=str(error))
    return result

def debug_image(image, metadata, deadline):
    selected_image = image
    identity = None
    selected_state = None
    if not metadata.get('debug_info') and metadata.get('debuglink'):
        name = metadata['debuglink']
        if not name or Path(name).name != name or name in ('.', '..') or '\\' in name:
            raise ValueError('invalid separate debug filename')
        matches = []
        found = False
        for path in (image.parent / name, image.parent / '.debug' / name):
            if not path.exists() and not path.is_symlink():
                continue
            found = True
            identity, state = file_identity(path, deadline)
            if identity['crc32'] == metadata['debuglink_crc']:
                matches.append((path, identity, state))
        if not matches:
            raise ValueError('separate debug file CRC does not match image' if found else 'separate debug file is missing')
        if len({identity['sha256'] for _, identity, _ in matches}) != 1:
            raise ValueError('ambiguous separate debug files')
        selected_image, identity, selected_state = matches[0]
    return selected_image, identity, selected_state

def artifacts(image, tool, debug_files):
    result = {'scope': 'split unit identities; not full type/inline verification', 'units': [], 'files': []}
    if not tool:
        return dict(result, status='unavailable', reason='requires host llvm-dwarfdump')
    deadline = time.monotonic() + 20
    try:
        image = Path(image).resolve(strict=True)
        from symbols import image_metadata
        metadata = image_metadata(image)
        selected_image, identity, selected_state = debug_image(image, metadata, deadline)
        if identity is not None:
            result['debug_image'] = dict(path=str(selected_image), **identity)
        units = references(dump(tool, selected_image, deadline))
        if selected_state is not None and selected_state != file_state(selected_image.stat()):
            raise ValueError('separate debug file changed during inspection')
        result['units'] = units
        explicit = [Path(path) for path in debug_files]
        paths = list(explicit)
        candidates = []
        for unit in units:
            name = Path(unit['name'])
            selected = [*explicit, name if name.is_absolute() else Path(unit['directory']) / name,
                        image.parent / name.name, selected_image.parent / name.name,
                        Path(str(image) + '.dwp'), Path(str(selected_image) + '.dwp')]
            candidates.append(selected)
            paths.extend(selected)
        paths = list(dict.fromkeys(path.absolute() for path in paths))
        if len(paths) > 256:
            raise ValueError('split-DWARF companion count exceeds limit')
        for path in paths:
            if time.monotonic() >= deadline:
                raise ValueError('split-DWARF inspection timed out')
            result['files'].append(companion(tool, path, deadline))
        indexes = {path: index for index, path in enumerate(paths)}
        for unit, selected in zip(units, candidates):
            unit['candidates'] = sorted({indexes[path.absolute()] for path in selected})
            unit['matches'] = [index for index in unit['candidates']
                               if unit['dwo_id'] in result['files'][index].get('dwo_ids', [])]
            states = {result['files'][index]['status'] for index in unit['candidates']}
            unit['status'] = 'matched' if unit['matches'] else 'mismatched' if 'available' in states else 'invalid' if 'invalid' in states else 'missing'
        if selected_state is not None and selected_state != file_state(selected_image.stat()):
            raise ValueError('separate debug file changed during inspection')
        result['status'] = 'not-referenced' if not units else 'matched' if all(unit['matches'] for unit in units) else 'incomplete'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result.update(status='unavailable', reason=str(error))
    return result

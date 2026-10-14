import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time


def dump(tool, path, deadline):
    process = subprocess.Popen([tool, '--debug-info', '--recurse-depth=0', '--debug-cu-index', '--', str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=dict(os.environ, LC_ALL='C'))
    output = bytearray()
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
                output.extend(block)
                if len(output) > 1024 * 1024:
                    raise ValueError('split-DWARF tool output exceeds limit')
        if process.wait(timeout=max(0.01, deadline - time.monotonic())):
            raise ValueError('split-DWARF tool failed')
        return output.decode('utf-8', errors='replace')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()

def unit_id(value):
    return '0x' + format(int(value, 16), '016x')

def references(text):
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
        if len(units) > 256:
            raise ValueError('split-DWARF unit count exceeds limit')
    return units

def companion(tool, path, deadline):
    result = {'path': str(path)}
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('debug companion must be a regular file')
        digest = hashlib.sha256()
        with os.fdopen(descriptor, 'rb') as file:
            descriptor = None
            for block in iter(lambda: file.read(1024 * 1024), b''):
                if time.monotonic() >= deadline:
                    raise ValueError('split-DWARF inspection timed out')
                digest.update(block)
        result['sha256'] = digest.hexdigest()
        text = dump(tool, path, deadline)
        split_info = text.partition('.debug_info.dwo contents:')[2]
        ids = re.findall(r'(?:DWO_id\s*=\s*|DW_AT_GNU_dwo_id\s+\()(0x[0-9a-fA-F]+)', split_info)
        ids += re.findall(r'(?m)^\s+[0-9]+\s+(0x[0-9a-fA-F]+)\s+\[', text)
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('debug companion changed during inspection')
        result['dwo_ids'] = sorted({unit_id(value) for value in ids})
        result['status'] = 'available' if ids else 'invalid'
    except FileNotFoundError:
        result['status'] = 'missing'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result.update(status='invalid', reason=str(error))
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return result

def artifacts(image, tool, debug_files):
    result = {'scope': 'split unit identities; not full type/inline verification', 'units': [], 'files': []}
    if not tool:
        return dict(result, status='unavailable', reason='requires host llvm-dwarfdump')
    deadline = time.monotonic() + 20
    try:
        image = Path(image).resolve(strict=True)
        units = references(dump(tool, image, deadline))
        result['units'] = units
        explicit = [Path(path) for path in debug_files]
        paths = list(explicit)
        candidates = []
        for unit in units:
            name = Path(unit['name'])
            selected = [*explicit, name if name.is_absolute() else Path(unit['directory']) / name,
                        Path(image).parent / name.name, Path(str(image) + '.dwp')]
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
        result['status'] = 'not-referenced' if not units else 'matched' if all(unit['matches'] for unit in units) else 'incomplete'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result.update(status='unavailable', reason=str(error))
    return result

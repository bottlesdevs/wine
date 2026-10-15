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

def inflate_section(source, section, destination, deadline):
    source.seek(section['offset'] + 12)
    remaining = section['size'] - 12
    decoder = zlib.decompressobj()
    written = 0
    try:
        with destination.open('wb') as output:
            while remaining:
                block = source.read(min(65536, remaining))
                if not block:
                    raise ValueError('truncated GNU-compressed debug data')
                remaining -= len(block)
                while True:
                    if time.monotonic() >= deadline:
                        raise ValueError('debug normalization timed out')
                    decoded = decoder.decompress(block, 65536)
                    block = decoder.unconsumed_tail
                    written += len(decoded)
                    if written > section['expanded']:
                        raise ValueError('GNU debug expansion exceeds declared size')
                    output.write(decoded)
                    if not block and len(decoded) < 65536:
                        break
            if not decoder.eof or decoder.unused_data or written != section['expanded']:
                raise ValueError('invalid GNU-compressed debug stream length')
    except zlib.error as error:
        raise ValueError('invalid GNU-compressed debug stream') from error

def normalize_debug_image(image, directory, deadline, helper):
    from symbols import host_tool, inline_output, image_metadata
    result = inline_output([str(helper), '--debug-compression', str(image)], dict(os.environ, LC_ALL='C'))
    if result.returncode:
        raise ValueError('GNU debug compression headers are invalid or exceed limits')
    sections = json.loads(result.stdout)['sections']
    if not sections:
        return image, None
    if image.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('GNU debug normalization input exceeds limit')
    tool = host_tool('llvm-objcopy') or host_tool('objcopy')
    if not tool:
        raise ValueError('GNU debug normalization requires host llvm-objcopy or objcopy')
    identity, _ = file_identity(image, deadline)
    arguments = []
    with image.open('rb') as source:
        for index, section in enumerate(sections):
            name = section['name']
            if not re.fullmatch(r'\.zdebug_[A-Za-z0-9_.]+', name):
                raise ValueError('unsupported GNU debug section name')
            target = Path(directory) / ('section-' + str(index))
            inflate_section(source, section, target, deadline)
            arguments.extend(['--update-section=' + name + '=' + str(target), '--rename-section=' + name + '=.debug_' + name[8:]])
    normalized = Path(directory) / 'normalized.elf'
    result = inline_output([tool, *arguments, str(image), str(normalized)], dict(os.environ, LC_ALL='C'))
    if result.returncode or normalized.stat().st_size > 512 * 1024 * 1024:
        raise ValueError('GNU debug normalization failed or exceeds limit')
    if image_metadata(normalized) != image_metadata(image):
        raise ValueError('GNU debug normalization changed image identity fields')
    normalized_identity, _ = file_identity(normalized, deadline)
    return normalized, dict(path=str(image), sha256=identity['sha256'], normalized_sha256=normalized_identity['sha256'],
                            compression='gnu-zlib', scope='temporary normalized ELF debug image')

def package_ids(text):
    index = text.partition('.debug_cu_index contents:')[2].partition('.debug_tu_index contents:')[0]
    return {unit_id(value) for value in re.findall(r'(?m)^\s+[0-9]+\s+(0x[0-9a-fA-F]+)\s+\[', index)}

def inline_package(image, paths, tool, deadline, directory):
    if not tool:
        raise ValueError('selected inline packages require host llvm-dwarfdump')
    needed = {unit['dwo_id'] for unit in references(dump(tool, image, deadline))}
    if not needed:
        return None, {}, None
    matches = []
    units = {}
    reasons = []
    for path in dict.fromkeys(paths):
        if time.monotonic() >= deadline:
            raise ValueError('inline package selection timed out')
        try:
            path = Path(path).resolve(strict=True)
            identity, before = file_identity(path, deadline)
            text = dump(tool, path, deadline)
            ids = package_ids(text)
            if before != file_state(path.stat()):
                raise ValueError('inline package changed during inspection')
            if needed <= ids:
                matches.append((dict(path=str(path), sha256=identity['sha256'], dwo_ids=sorted(needed),
                                     status='matched', scope='selected DWP unit identities'), {path: before}, path))
            elif not ids:
                split = text.partition('.debug_info.dwo contents:')[2]
                found = {unit_id(value) for value in re.findall(r'(?:DWO_id\s*=\s*|DW_AT_GNU_dwo_id\s+\()(0x[0-9a-fA-F]+)', split)}
                for identifier in needed & found:
                    units.setdefault(identifier, []).append((path, identity['sha256'], before))
            else:
                raise ValueError('inline package does not contain all image DWO identities')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            reasons.append(str(error))
    if matches:
        if len({record['sha256'] for record, _, _ in matches}) != 1:
            raise ValueError('ambiguous matching inline DWP packages')
        return matches[0]
    if not needed <= units.keys():
        raise ValueError('no matching inline DWP or complete DWO set: ' + '; '.join(reasons)[:1024])
    selected = {}
    for identifier in sorted(needed):
        candidates = units[identifier]
        if len({digest for _, digest, _ in candidates}) != 1:
            raise ValueError('ambiguous matching inline DWO inputs')
        path, digest, state = candidates[0]
        selected[path] = (digest, state)
    if sum(path.stat().st_size for path in selected) > 256 * 1024 * 1024:
        raise ValueError('inline DWO inputs exceed limit')
    from symbols import host_tool, inline_output
    packager = host_tool('llvm-dwp')
    if not packager:
        raise ValueError('selected inline DWO inputs require host llvm-dwp')
    target = Path(directory) / 'selected.dwp'
    response = Path(directory) / 'inputs.txt'
    if any(ord(character) < 32 for path in selected for character in str(path)):
        raise ValueError('inline DWO path contains a control character')
    response.write_text(''.join(json.dumps(str(path), ensure_ascii=False) + '\n' for path in selected))
    try:
        result = inline_output([packager, '@' + str(response), '-o', str(target)], dict(os.environ, LC_ALL='C'))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise ValueError('inline DWO package assembly failed: ' + str(error)) from error
    if result.returncode:
        raise ValueError('inline DWO package assembly failed')
    if target.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('inline DWO package exceeds limit')
    identity, state = file_identity(target, deadline)
    if not needed <= package_ids(dump(tool, target, deadline)):
        raise ValueError('assembled inline DWP is missing image DWO identities')
    states = {path: before for path, (_, before) in selected.items()}
    states[target] = state
    record = dict(sha256=identity['sha256'], dwo_ids=sorted(needed), status='matched',
                  scope='selected DWO unit identities; temporary DWP assembly',
                  inputs=[dict(path=str(path), sha256=digest) for path, (digest, _) in selected.items()])
    return record, states, target

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

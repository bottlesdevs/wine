import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import posixpath
import re
import stat
import subprocess
import time

from dwarf import debug_image, dump, file_identity, file_state


def line_files(text):
    entries = []
    for table in re.split(r'(?m)^debug_line\[(0x[0-9a-fA-F]+)\]\s*$', text)[1:][1::2]:
        directories = {int(match[1]): json.loads(match[2]) for match in
                       re.finditer(r'(?m)^include_directories\[\s*(\d+)\]\s*=\s*(".*")\s*$', table)}
        for match in re.finditer(r'(?ms)^file_names\[\s*(\d+)\]:\s*\n(.*?)(?=^file_names\[|\Z)', table):
            body = match[2]
            name = re.search(r'(?m)^\s*name:\s*(".*")\s*$', body)
            directory = re.search(r'(?m)^\s*dir_index:\s*(\d+)\s*$', body)
            if not name:
                raise ValueError('DWARF file entry has no name')
            name = json.loads(name[1])
            parent = directories.get(int(directory[1]), '') if directory else ''
            windows = '\\' in name or '\\' in parent or bool(re.match(r'^[A-Za-z]:', name) or re.match(r'^[A-Za-z]:', parent))
            kind = PureWindowsPath if windows else PurePosixPath
            path = kind(name) if kind(name).is_absolute() else kind(parent) / name
            logical = ntpath.normpath(str(path)) if windows else posixpath.normpath(str(path))
            checksum = None
            if re.search(r'(?m)^\s*md5_checksum:', body):
                value = re.search(r'(?m)^\s*md5_checksum:\s*([0-9a-fA-F]{32})\s*$', body)
                if not value:
                    raise ValueError('invalid DWARF source checksum')
                checksum = value[1].lower()
            entry = {'path': logical, 'name': path.name, 'md5': checksum}
            if entry not in entries:
                entries.append(entry)
            if len(entries) > 4096:
                raise ValueError('DWARF source file count exceeds limit')
    return entries


def source_identity(path, deadline):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('source must be a regular file')
        sha256, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
        for block in iter(lambda: file.read(1024 * 1024), b''):
            if time.monotonic() >= deadline:
                raise ValueError('source inspection timed out')
            sha256.update(block)
            md5.update(block)
    if file_state(before) != file_state(path.stat()):
        raise ValueError('source changed during inspection')
    return {'sha256': sha256.hexdigest(), 'md5': md5.hexdigest()}


def inspect_sources(image, tool, files, expected_sha256=None):
    result = {'scope': 'DWARF source checksums; not type/inline or source authenticity verification', 'entries': [], 'files': []}
    if not tool:
        return dict(result, status='unavailable', reason='requires host llvm-dwarfdump')
    deadline = time.monotonic() + 20
    try:
        from symbols import image_metadata
        image = Path(image).resolve(strict=True)
        image_identity, image_state = file_identity(image, deadline)
        if expected_sha256 is not None and image_identity['sha256'] != expected_sha256:
            raise ValueError('image changed during source query')
        metadata = image_metadata(image)
        selected, identity, selected_state = debug_image(image, metadata, deadline)
        selected_state = selected_state if selected_state is not None else image_state
        if identity is not None:
            result['debug_image'] = dict(path=str(selected), **identity)
        keep = True
        def header(line):
            nonlocal keep
            if line.startswith(b'debug_line['):
                keep = True
            elif line.startswith(b'Address ') and b'Line' in line:
                keep = False
            return keep
        text = dump(tool, selected, deadline, arguments=['--debug-line'], line_filter=header,
                    input_limit=256 * 1024 * 1024)
        entries = line_files(text)
        result['entries'] = entries
        for value in files:
            if time.monotonic() >= deadline:
                raise ValueError('source inspection timed out')
            path = Path(value)
            report = {'path': str(path)}
            try:
                actual = source_identity(path, deadline)
                candidates = [index for index, entry in enumerate(entries) if entry['name'] == path.name]
                matches = [index for index in candidates if entries[index]['md5'] == actual['md5']]
                recorded = [index for index in candidates if entries[index]['md5'] is not None]
                status = 'matched' if matches else 'mismatched' if recorded else 'not-recorded' if candidates else 'not-referenced'
                report.update(actual, status=status, candidates=candidates, matches=matches)
            except FileNotFoundError:
                report['status'] = 'missing'
            except (OSError, ValueError) as error:
                report.update(status='invalid', reason=str(error))
            result['files'].append(report)
        if selected_state != file_state(selected.stat()) or image_state != file_state(image.stat()):
            raise ValueError('debug image changed during source inspection')
        result['status'] = 'available' if any(entry['md5'] is not None for entry in entries) else 'not-recorded'
        if len(json.dumps(result).encode()) > 512 * 1024:
            raise ValueError('source checksum report exceeds limit')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result.update(status='unavailable', reason=str(error), entries=[], files=[])
    return result

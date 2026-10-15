import os
import stat
import shutil
import subprocess
import struct
import uuid
import json
import re
import selectors
import tempfile
import time
from pathlib import Path, PureWindowsPath

def host_path(value, prefix):
    value = value.removeprefix("\\\\?\\")
    if value.startswith("/"):
        return Path(value)
    if len(value) > 2 and value[1] == ":":
        root = Path(prefix) / "dosdevices" / value[:2].lower()
        if value[0].lower() == "z" and not root.exists():
            root = Path("/")
        relative = value[3:].replace("\\", "/")
        path = root / relative
        if path.exists():
            return path
        current = root
        for part in Path(relative).parts:
            exact = current / part
            if exact.exists():
                current = exact
                continue
            try:
                matches = [entry for entry in current.iterdir() if entry.name.casefold() == part.casefold()]
            except OSError:
                return path
            if len(matches) != 1:
                return path
            current = matches[0]
        return current
    return None

def image_metadata(image):
    with Path(image).open('rb') as file:
        elf = file.read(4) == b'\x7fELF'
    native = Path(__file__).resolve().parent / ('native/eagle-elf' if elf else 'native/eagle-pe')
    result = subprocess.run([str(native), str(image)], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

def disassemble(image, rva, size=64):
    if not 1 <= size <= 256:
        raise ValueError('disassembly exceeds byte limit')
    metadata = image_metadata(image)
    base = int(metadata['image_base'], 0)
    offset = int(rva, 0)
    if not 0 <= offset < metadata['size']:
        raise ValueError('instruction address is outside the image')
    tool = shutil.which('objdump' if metadata.get('format') == 'ELF' else 'x86_64-w64-mingw32-objdump' if metadata['machine'] == 0x8664 else 'i686-w64-mingw32-objdump')
    if not tool:
        return {'status': 'disassembler unavailable'}
    result = subprocess.run([tool, '-d', '-M', 'intel', '--insn-width=16', '--start-address=' + hex(base + offset), '--stop-address=' + hex(base + offset + size), str(image)], capture_output=True, text=True, timeout=10)
    if result.returncode:
        return {'status': 'disassembly failed'}
    lines = [line.strip() for line in result.stdout.splitlines() if re.match(r'^\s*[0-9a-f]+:', line)]
    return {'status': 'available' if lines else 'instructions unavailable', 'origin': 'exact PE file', 'runtime_bytes_verified': False, 'instructions': lines[:64]}

def resolve(image, rvas):
    if not rvas:
        return []
    if len(rvas) > 256:
        raise ValueError("symbol query exceeds frame limit")
    image = Path(image).resolve(strict=True)
    metadata = image_metadata(image)
    base = int(metadata['image_base'], 0)
    machine = metadata['machine']
    if metadata.get('format') != 'ELF' and machine not in (0x14c, 0x8664):
        tool = host_tool('llvm-symbolizer')
        if not tool or not (metadata.get('debug_info') or metadata.get('debuglink')):
            return []
        return resolve_llvm(image, rvas, tool, 'llvm-exact-image')
    tool = shutil.which('addr2line' if metadata.get('format') == 'ELF' else "x86_64-w64-mingw32-addr2line" if machine == 0x8664 else "i686-w64-mingw32-addr2line") or shutil.which("addr2line")
    if not tool:
        return []
    addresses = [hex(base + int(rva, 0)) for rva in rvas]
    result = subprocess.run([tool, "-f", "-C", "-e", str(image), *addresses], capture_output=True, text=True, timeout=10)
    if result.returncode:
        return []
    lines = result.stdout.splitlines()
    if len(lines) != len(rvas) * 2:
        return []
    output = []
    for index in range(len(rvas)):
        name, source = lines[index * 2:index * 2 + 2]
        value = {"symbol": None if name == "??" else name, "source": None if source.startswith("??") else source, "resolver": "binutils-exact-image"}
        location = re.fullmatch(r'(.*):([0-9]+)(?: \(discriminator [0-9]+\))?', source)
        if location and not source.startswith('??'):
            value.update(file=location[1], line=int(location[2]))
        output.append(value)
    located = [index for index, frame in enumerate(output) if frame.get('file')]
    if metadata.get('format') == 'ELF' and located:
        llvm = host_tool('llvm-symbolizer')
        reason = 'requires host llvm-symbolizer'
        resolved = []
        if llvm:
            try:
                resolved = resolve_llvm(image, addresses, llvm, 'llvm-exact-image')
                reason = 'matching function name unavailable'
            except (OSError, ValueError, subprocess.SubprocessError):
                reason = 'LLVM source resolver failed'
        for index in located:
            frame = output[index]
            if resolved and resolved[index]['symbol']:
                selected = resolved[index]
                if (selected.get('file'), selected.get('line')) == (frame['file'], frame['line']):
                    if selected['symbol'] != frame['symbol']:
                        output[index] = selected
                    continue
                frame['symbol_reason'] = 'resolver source locations disagree'
            elif llvm or not frame['symbol']:
                frame['symbol_reason'] = reason
    return output

def host_tool(name):
    tool = shutil.which(name)
    if tool:
        return tool
    versions = []
    for directory in os.get_exec_path():
        for path in Path(directory).glob(name + '-[0-9]*'):
            match = re.fullmatch(re.escape(name) + r'-([0-9]+)', path.name)
            if match and path.is_file() and os.access(path, os.X_OK):
                versions.append((int(match[1]), str(path)))
    return max(versions, default=(0, None))[1]

def pdb_resolver():
    return host_tool('llvm-symbolizer')

def inline_output(arguments, environment):
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment)
    deadline = time.monotonic() + 10
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError('inline resolver timed out')
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    break
                output.extend(block)
                if len(output) > 16 * 1024 * 1024:
                    raise ValueError('inline resolver output exceeds limit')
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return subprocess.CompletedProcess(arguments, code, output.decode('utf-8'), '')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()

def resolve_llvm(image, rvas, tool, origin, inlines=False, dwp=None):
    flags = [] if inlines else ['--no-inlines']
    if dwp is not None:
        flags.append('--dwp=' + str(dwp))
    arguments = [tool, '--obj=' + str(image), '--relative-address', '--output-style=JSON', *flags, '--no-debuginfod', *rvas]
    environment = {key: value for key, value in os.environ.items() if key != 'LLVM_SYMBOLIZER_OPTS'}
    result = inline_output(arguments, environment) if inlines else subprocess.run(
        arguments, capture_output=True, text=True, timeout=10, env=environment)
    try:
        values = json.loads(result.stdout)
        if result.returncode or not isinstance(values, list) or len(values) != len(rvas):
            raise ValueError('invalid resolver response')
        output = []
        for address, value in zip(rvas, values):
            if int(value['Address'], 0) != int(address, 0) or 'Error' in value:
                raise ValueError('invalid resolver address')
            frames = value['Symbol']
            if not isinstance(frames, list) or not frames or len(frames) > (64 if inlines else 1):
                raise ValueError('invalid inline frame count')
            parsed = []
            for frame in frames:
                name, filename, line = frame['FunctionName'], frame['FileName'], frame['Line']
                if not isinstance(name, str) or not isinstance(filename, str) or type(line) is not int or line < 0:
                    raise ValueError('invalid source frame')
                item = {'symbol': None if name in ('', '??') else name, 'source': None, 'resolver': origin}
                if filename and filename != '??' and line > 0:
                    item.update(file=filename, line=line, source=filename + ':' + str(line))
                if inlines:
                    column = frame.get('Column', 0)
                    if type(column) is not int or column < 0:
                        raise ValueError('invalid source column')
                    item.update(column=column, inlined=len(parsed) < len(frames) - 1,
                                status='source-resolved' if item.get('file') else 'symbol-only' if item['symbol'] else 'unresolved')
                parsed.append(item)
            item = dict(parsed[0])
            if inlines:
                item['inline_frames'] = parsed
            output.append(item)
        return output
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError('inline source resolver failed: ' + str(error) if inlines else 'source resolver failed') from error

def resolve_pdb(image, pdb, names, rvas, inlines=False):
    if not rvas:
        return []
    tool = pdb_resolver()
    if not tool:
        raise ValueError('PDB source resolver unavailable (requires llvm-symbolizer)')
    if not names or any(not name or name in ('.', '..') for name in names):
        raise ValueError('PDB debug filename is missing')
    with tempfile.TemporaryDirectory(prefix='eagle-symbols-') as directory:
        root = Path(directory)
        image_name = next('module-' + str(index) + '.exe' for index in range(len(names) + 1)
                          if 'module-' + str(index) + '.exe' not in names)
        selected = root / image_name
        selected.symlink_to(Path(image).resolve(strict=True))
        for name in set(names):
            (root / name).symlink_to(Path(pdb).resolve(strict=True))
        try:
            return resolve_llvm(selected, rvas, tool, 'llvm-matched-pdb', inlines=inlines)
        except ValueError as error:
            raise ValueError('PDB source resolver failed') from error

def resolve_inlines(image, rvas, pdb, names, expected_sha256, debug_files=None):
    with tempfile.TemporaryDirectory(prefix='eagle-inlines-') as directory:
        return resolve_inline_files(image, rvas, pdb, names, expected_sha256, debug_files, directory)

def resolve_inline_files(image, rvas, pdb, names, expected_sha256, debug_files, directory):
    from dwarf import debug_image, file_identity, file_state, inline_package
    tool = host_tool('llvm-symbolizer')
    if not tool:
        raise ValueError('inline lookup requires host llvm-symbolizer')
    deadline = time.monotonic() + 20
    image = Path(image).resolve(strict=True)
    identity, state = file_identity(image, deadline)
    if identity['sha256'] != expected_sha256:
        raise ValueError('image changed during inline lookup')
    states = {image: state}
    package = None
    package_path = None
    metadata = image_metadata(image)
    if pdb:
        pdb = Path(pdb).resolve(strict=True)
        _, states[pdb] = file_identity(pdb, deadline)
        selected = pdb_identity(pdb)
        if any((value['guid'], value['age']) != (selected['guid'], selected['age']) for value in metadata.get('codeview', [])):
            raise ValueError('PDB changed during inline lookup')
        values = resolve_pdb(image, pdb, names, rvas, inlines=True)
    else:
        if metadata.get('codeview'):
            raise ValueError('CodeView inline lookup requires a selected matching PDB')
        selected, _, state = debug_image(image, metadata, deadline)
        if state is not None:
            states[selected] = state
        if metadata.get('format') == 'ELF':
            paths = debug_files or [path for path in dict.fromkeys((Path(str(selected) + '.dwp'), Path(str(image) + '.dwp')))
                                    if path.exists() or path.is_symlink()]
            if paths:
                package, selected_states, package_path = inline_package(selected, paths, host_tool('llvm-dwarfdump'), deadline, directory)
                states.update(selected_states)
        addresses = [hex(int(metadata['image_base'], 0) + int(value, 0)) for value in rvas] if metadata.get('format') == 'ELF' else rvas
        options = {'dwp': package_path} if package_path else {}
        values = resolve_llvm(selected, addresses, tool, 'llvm-exact-image', inlines=True, **options)
    if any(state != file_state(path.stat()) for path, state in states.items()):
        raise ValueError('inline debug artifacts changed during lookup')
    if time.monotonic() >= deadline:
        raise ValueError('inline lookup timed out')
    return [value['inline_frames'] for value in values], package

def query(image, pdb=None, rvas=None, artifacts=False, debug_files=None, sources=False, source_files=None,
          runner_root=None, source_maps=None, inlines=False):
    if type(inlines) is not bool or (inlines and rvas is None):
        raise ValueError('inlines must be a boolean and requires rvas')
    if runner_root is not None and (not isinstance(runner_root, (str, os.PathLike)) or not str(runner_root) or len(str(runner_root)) > 4096):
        raise ValueError('runner_root must be a path')
    if source_maps is not None:
        from build_sources import validate_maps
        validate_maps(source_maps)
        if runner_root is None:
            raise ValueError('source_maps requires runner_root')
    if type(sources) is not bool:
        raise ValueError('sources must be a boolean')
    if source_files is not None and (not isinstance(source_files, list) or len(source_files) > 256 or
                                    any(not isinstance(path, str) or not path or len(path) > 4096 for path in source_files)):
        raise ValueError('source_files must be a list of at most 256 paths')
    if type(artifacts) is not bool:
        raise ValueError('artifacts must be a boolean')
    if debug_files is not None and (not isinstance(debug_files, list) or len(debug_files) > 256 or
                                   any(not isinstance(path, str) or not path for path in debug_files)):
        raise ValueError('debug_files must be a list of at most 256 paths')
    if rvas is not None:
        if not isinstance(rvas, list) or len(rvas) > 256:
            raise ValueError("rvas must be a list of at most 256 addresses")
        offsets = []
        for value in rvas:
            if type(value) not in (str, int):
                raise ValueError("RVA must be an integer or numeric string")
            offset = int(value, 0) if isinstance(value, str) else value
            if offset < 0:
                raise ValueError("symbol address is outside the image")
            offsets.append(offset)
    from session import identity
    result = identity(image)
    if pdb:
        if result.get('format') == 'ELF':
            raise ValueError('PDB matching requires a PE image')
        found = pdb_identity(pdb)
        result['pdb_identity'] = found
        result['pdb_matches'] = any(entry['guid'] == found['guid'] and entry['age'] == found['age'] for entry in result['codeview'])
        if not result['pdb_matches']:
            raise ValueError('PDB GUID or age does not match the PE image')
    if rvas is not None:
        if any(offset >= result['size'] for offset in offsets):
            raise ValueError('symbol address is outside the image')
        addresses = [hex(offset) for offset in offsets]
        if pdb:
            if any(entry['guid'] != found['guid'] or entry['age'] != found['age'] for entry in result['codeview']):
                raise ValueError('ambiguous PDB identities in the PE image')
            names = [Path(entry['pdb']).name if entry['pdb'].startswith('/') else PureWindowsPath(entry['pdb']).name
                     for entry in result['codeview']]
            frames = resolve_pdb(image, pdb, names, addresses)
        else:
            frames = resolve(image, addresses)
        if len(frames) != len(offsets):
            raise ValueError('symbol resolver unavailable or failed')
        result['resolved'] = []
        for offset, frame in zip(offsets, frames):
            status = 'source-resolved' if frame.get('file') and frame.get('line') else 'symbol-only' if frame.get('symbol') else 'unresolved'
            result['resolved'].append(dict(frame, rva=hex(offset), status=status))
        if inlines:
            result['inline_order'] = 'innermost-to-outermost'
            try:
                chains, package = resolve_inlines(image, addresses, pdb, names if pdb else [], result['sha256'], debug_files) if addresses else ([], None)
                if package:
                    result['inline_artifacts'] = package
                for frame, chain in zip(result['resolved'], chains):
                    status = 'available' if len(chain) > 1 and any(value['symbol'] for value in chain[:-1]) else 'not-reported' if any(value['symbol'] or value.get('file') for value in chain) else 'unresolved'
                    frame.update(inline_frames=chain, inline_status=status)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                for frame in result['resolved']:
                    frame.update(inline_frames=[], inline_status='unavailable', inline_reason=str(error))
    if artifacts or debug_files is not None:
        if result.get('format') != 'ELF':
            raise ValueError('split-DWARF artifacts require an ELF image')
        from dwarf import artifacts as inspect_artifacts
        result['split_dwarf'] = inspect_artifacts(image, host_tool('llvm-dwarfdump'), debug_files or [])
    if sources or source_files is not None:
        from sources import inspect_sources
        result['source_checksums'] = inspect_sources(image, host_tool('llvm-dwarfdump'), source_files or [], expected_sha256=result['sha256'])
    if runner_root is not None:
        from build_sources import inspect_build_sources
        result['build_sources'] = inspect_build_sources(image, runner_root, source_maps or [], result['sha256'])
    if sources or source_files is not None or runner_root is not None:
        if len(json.dumps(result).encode()) > 768 * 1024:
            raise ValueError('source query response exceeds limit')
    return result

def pdb_identity(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("PDB must be a regular file")
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "rb") as file:
        header = file.read(56)
        if len(header) != 56:
            raise ValueError("truncated PDB header")
        if not header.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"):
            raise ValueError("unsupported PDB container")
        block_size, free_map, blocks, directory_size, reserved, map_block = struct.unpack("<6I", header[32:56])
        length = info.st_size
        if block_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) or blocks * block_size > length or directory_size > 16 * 1024 * 1024:
            raise ValueError("invalid PDB directory bounds")
        def block(number):
            if number >= blocks: raise ValueError("PDB block out of bounds")
            file.seek(number * block_size)
            value = file.read(block_size)
            if len(value) != block_size: raise ValueError("truncated PDB block")
            return value
        count = (directory_size + block_size - 1) // block_size
        mapping = block(map_block)
        if count * 4 > len(mapping): raise ValueError("unsupported oversized PDB block map")
        directory = b"".join(block(number) for number in struct.unpack(f"<{count}I", mapping[:count * 4]))[:directory_size]
        if len(directory) < 4:
            raise ValueError("truncated PDB stream directory")
        streams = struct.unpack_from("<I", directory)[0]
        if streams < 2 or streams > 65536 or 4 + streams * 4 > len(directory): raise ValueError("invalid PDB streams")
        sizes = struct.unpack_from(f"<{streams}I", directory, 4)
        position = 4 + streams * 4
        for index, size in enumerate(sizes):
            entries = 0 if size == 0xffffffff else (size + block_size - 1) // block_size
            if position + entries * 4 > len(directory): raise ValueError("invalid PDB stream blocks")
            numbers = struct.unpack_from(f"<{entries}I", directory, position)
            if index == 1:
                if size < 28 or not numbers: raise ValueError("PDB identity stream is missing")
                value = block(numbers[0])[:28]
                version, signature, age = struct.unpack_from("<3I", value)
                return {"guid": str(uuid.UUID(bytes_le=value[12:28])), "age": age}
            position += entries * 4
        raise ValueError("PDB identity not found")

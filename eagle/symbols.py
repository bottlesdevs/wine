import shutil
import subprocess
import struct
import uuid
import json
import re
from pathlib import Path

def host_path(value, prefix):
    value = value.removeprefix("\\\\?\\")
    if value.startswith("/"):
        return Path(value)
    if len(value) > 2 and value[1] == ":":
        if value[0].lower() == "z":
            root = Path("/")
        else:
            root = Path(prefix) / "dosdevices" / value[:2].lower()
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
    image = Path(image).resolve(strict=True)
    metadata = image_metadata(image)
    base = int(metadata['image_base'], 0)
    machine = metadata['machine']
    tool = shutil.which('addr2line' if metadata.get('format') == 'ELF' else "x86_64-w64-mingw32-addr2line" if machine == 0x8664 else "i686-w64-mingw32-addr2line") or shutil.which("addr2line")
    if not tool:
        return []
    if len(rvas) > 256:
        raise ValueError("symbol query exceeds frame limit")
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
    return output

def pdb_identity(path):
    with Path(path).open("rb") as file:
        header = file.read(56)
        if len(header) != 56:
            raise ValueError("truncated PDB header")
        if not header.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"):
            raise ValueError("unsupported PDB container")
        block_size, free_map, blocks, directory_size, reserved, map_block = struct.unpack("<6I", header[32:56])
        length = Path(path).stat().st_size
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

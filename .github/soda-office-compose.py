import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def verify(root, files):
    for name, record in files.items():
        path = root / name
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        if record['kind'] == 'symlink':
            assert path.is_symlink() and os.readlink(path) == record['target'], name
        else:
            assert not path.is_symlink() and path.resolve().is_relative_to(root), name
            assert path.stat().st_size == record['size'] and digest(path) == record['sha256'], name


def compose(runner, binaries, source):
    runner = runner.resolve(strict=True)
    files = json.loads((runner / 'share/soda/files.json').read_text())
    assert not (runner / 'share/soda/office-composition.json').exists()
    verify(runner, files)
    replacement = {}
    for bits, machine in ((32, 0x14c), (64, 0x8664)):
        path = binaries / f'eagle-debug{bits}.exe'
        assert not path.is_symlink()
        with path.open('rb') as file:
            header = file.read(4096)
        assert header[:2] == b'MZ'
        offset, = struct.unpack_from('<I', header, 0x3c)
        assert header[offset:offset + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', header, offset + 4)[0] == machine
        name = f'lib/eagle/native/eagle-debug{bits}.exe'
        assert files[name]['kind'] == 'pe'
        replacement[name] = {'kind': 'pe', 'size': path.stat().st_size, 'sha256': digest(path), 'machine': machine}
    destination = runner.with_name(runner.name + '-office-' + source['revision'][:12])
    assert not destination.exists()
    shutil.copytree(runner, destination, symlinks=True, copy_function=os.link)
    for name in replacement:
        path = destination / name
        assert path.parent.resolve().is_relative_to(destination)
        temporary = path.with_name(path.name + '.next')
        assert not temporary.exists()
        shutil.copyfile(binaries / path.name, temporary)
        temporary.chmod(0o755)
        temporary.replace(path)
    verify(destination, dict(files, **replacement))
    verify(runner, {name: files[name] for name in replacement})
    receipt = {'schema': 1, 'scope': 'Office test composition; original runner metadata describes the verified input',
               'runner': str(destination), 'base_runner': str(runner),
               'base_manifest_sha256': digest(runner / 'share/soda/files.json'),
               'debugger_source': source, 'replacements': replacement,
               'unchanged_files': len(files) - len(replacement), 'base_collectors_unchanged': True}
    (destination / 'share/soda/office-composition.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    repo = Path(__file__).resolve().parent.parent
    source = {'revision': subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip(),
              'file': 'eagle/native/debugger.c', 'sha256': digest(repo / 'eagle/native/debugger.c'),
              'compilers': {arch: subprocess.check_output([arch + '-w64-mingw32-gcc', '--version'], text=True).splitlines()[0]
                            for arch in ('x86_64', 'i686')}}
    print(json.dumps(compose(Path(sys.argv[1]), Path(sys.argv[2]), source), indent=2))

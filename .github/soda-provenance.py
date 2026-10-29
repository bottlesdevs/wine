import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'eagle'))
from provenance import digest, source_identity

METADATA = ('share/soda/build.json', 'share/soda/files.json', 'share/soda/sources.json')

def assignments(values):
    result = {}
    for value in values:
        name, separator, path = value.partition('=')
        if not separator or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', name) or not path or name in result:
            raise ValueError('invalid or duplicate named input')
        result[name] = path
    return result

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.' + path.name, delete=False) as file:
            temporary = Path(file.name)
            json.dump(value, file, sort_keys=True, indent=2)
            file.write('\n')
        temporary.chmod(0o644)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

def file_inventory(runner, tools):
    records = {}
    fields = ('format', 'machine', 'timestamp', 'size', 'image_base', 'build_id', 'codeview', 'debug_info', 'debuglink', 'debuglink_crc')
    for directory, names, files in os.walk(runner, followlinks=False):
        for name in sorted(names + files):
            path = Path(directory) / name
            relative = str(path.relative_to(runner))
            if relative in METADATA:
                continue
            if path.is_symlink():
                records[relative] = {'kind': 'symlink', 'target': os.readlink(path)}
                continue
            info = path.stat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('runner entry must be a regular file or symlink: ' + relative)
            record = {'kind': 'file', 'size': info.st_size, 'sha256': digest(path)}
            with path.open('rb') as file:
                header = file.read(64)
                if header[:2] == b'MZ' and len(header) == 64:
                    offset = int.from_bytes(header[60:64], 'little')
                    file.seek(offset)
                    pe = file.read(4) == b'PE\0\0'
                else:
                    pe = False
            kind = 'elf' if header[:4] == b'\x7fELF' else 'pe' if pe else None
            if kind:
                arguments = ['--debug'] if kind == 'pe' and path.suffix == '.debug' else []
                output = subprocess.check_output([str(tools / ('eagle-' + kind)), *arguments, str(path)], text=True, timeout=10)
                metadata = json.loads(output)
                record.update(kind=kind, identity={key: metadata[key] for key in fields if key in metadata})
            after = path.stat()
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('runner file changed during inspection: ' + relative)
            records[relative] = record
    return records

def package_metadata(runner, tools, name, sources, expected, patches=None, inputs=None, config_root=None,
                     refresh=False, prebuilt=False, assembly=None):
    runner, tools = Path(runner).resolve(strict=True), Path(tools).resolve(strict=True)
    if not re.fullmatch(r'[-A-Za-z0-9._+]{1,128}', name) or len(sources) > 32:
        raise ValueError('invalid runner component or source count')
    summary_path, files_path, sources_path = [runner / path for path in METADATA]
    if any(path.is_symlink() for path in (runner / 'share', runner / 'share/soda', summary_path, files_path, sources_path)):
        raise ValueError('runner metadata paths must not be symlinks')
    if refresh:
        if sources or patches or inputs or config_root or expected:
            raise ValueError('refresh cannot replace recorded build inputs')
        if summary_path.is_file() and sources_path.is_file():
            previous = json.loads(summary_path.read_text())
            if not isinstance(previous, dict) or type(previous.get('schema')) is not int or previous['schema'] != 1 or digest(sources_path) != previous.get('sources_sha256'):
                raise ValueError('recorded source inventory does not match its manifest')
            provenance = json.loads(sources_path.read_text())
        elif summary_path.exists() or sources_path.exists():
            raise ValueError('recorded source provenance is incomplete')
        elif prebuilt:
            provenance = {'status': 'unavailable', 'reason': 'prebuilt artifact has no recorded source provenance',
                          'sources': {}, 'patches': {}, 'inputs': {}}
        else:
            raise ValueError('recorded source provenance is unavailable')
    else:
        if not sources:
            raise ValueError('new runner metadata requires source inputs')
        provenance = {'status': 'recorded', 'sources': {}, 'patches': {}, 'inputs': {}}
        for label, source in sources.items():
            identity = source_identity(source)
            if label in expected and identity['revision'] != expected[label]:
                raise ValueError('source revision mismatch: ' + label)
            provenance['sources'][label] = identity
        if set(expected) - set(sources):
            raise ValueError('expected source is absent')
        if patches:
            provenance['patches'] = {path.name: digest(path) for path in sorted(Path(patches).glob('*.mypatch'))}
        for label, path in (inputs or {}).items():
            provenance['inputs'][label] = digest(path)
        if config_root:
            root = Path(config_root).resolve(strict=True)
            provenance['configuration'] = {str(path.relative_to(root)): digest(path)
                                           for path in sorted(root.rglob('config.*'))
                                           if path.name in ('config.status', 'config.log', 'config.cache') and path.is_file() and not path.is_symlink()}
    records = file_inventory(runner, tools)
    launcher = records.get('bin/wine')
    if not launcher or launcher['kind'] != 'elf':
        raise ValueError('runner bin/wine must be a regular ELF launcher')
    summary = {'schema': 1, 'component': name, 'scope': 'runner files and supplied build inputs; symlink targets are not followed',
               'source_status': provenance['status'],
               'source_identities': {label: {key: value[key] for key in ('revision', 'dirty', 'tree_sha256')}
                                     for label, value in provenance['sources'].items()},
               'wine': launcher, 'file_count': len(records),
               'binary_count': sum(value['kind'] in ('elf', 'pe') for value in records.values()),
               'patch_inventory_scope': 'supplied patch files; application order is not attested'}
    if assembly:
        provenance['assembly_source'] = source_identity(assembly)
    if 'assembly_source' in provenance:
        identity = provenance['assembly_source']
        summary['assembly_source_identity'] = {key: identity[key] for key in ('revision', 'dirty', 'tree_sha256')}
    write_json(sources_path, provenance)
    write_json(files_path, records)
    summary.update(sources_sha256=digest(sources_path), files_sha256=digest(files_path))
    write_json(summary_path, summary)
    return summary

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('runner')
    parser.add_argument('--tools', required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--source', action='append', default=[])
    parser.add_argument('--expect-source', action='append', default=[])
    parser.add_argument('--patch-dir')
    parser.add_argument('--input', action='append', default=[])
    parser.add_argument('--config-root')
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--prebuilt', action='store_true')
    parser.add_argument('--assembly-source')
    args = parser.parse_args()
    package_metadata(args.runner, args.tools, args.name, assignments(args.source), assignments(args.expect_source),
                     args.patch_dir, assignments(args.input), args.config_root, args.refresh, args.prebuilt, args.assembly_source)

if __name__ == '__main__':
    main()

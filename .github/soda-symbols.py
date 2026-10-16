import argparse
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'eagle'))
from provenance import digest
from symbols import host_tool, pdb_identity
from dwarf import companion, dump, file_identity, references


def split_references(debug):
    limit = 64 * 1024 * 1024
    text = dump('readelf', debug, time.monotonic() + 60,
                arguments=['--debug-dump=info', '--debug-dump=no-follow-links', '--dwarf-depth=1'], output_limit=limit)
    if not re.search(r'DW_AT_(?:GNU_)?dwo_name|DW_UT_skeleton', text):
        return [], None
    dumper = host_tool('llvm-dwarfdump')
    if not dumper:
        raise ValueError('split symbols require existing host llvm-dwarfdump')
    found = references(dump(dumper, debug, time.monotonic() + 60, output_limit=limit), limit=65536)
    if not found:
        raise ValueError('split debug image has no DWO identities: ' + str(debug))
    return found, dumper


def split_inputs(plans, runner, roots):
    units, candidates = {}, {}
    dumper = None
    limit = 64 * 1024 * 1024
    for image, relative, existing, metadata in plans:
        if metadata.get('format') != 'ELF':
            continue
        debug = existing or image
        found, selected_tool = split_references(debug)
        if not found:
            continue
        dumper = selected_tool
        units[str(image.relative_to(runner))] = (relative, found)
    if not units:
        return {}, None
    for root in dict.fromkeys([runner, *roots]):
        root = Path(root).absolute()
        if root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError('debug root must be a directory without symlinks')
        for directory, names, files in os.walk(root, followlinks=False):
            names[:] = [name for name in names if not (Path(directory) / name).is_symlink()]
            for name in files:
                path = Path(directory) / name
                if path.suffix in ('.dwo', '.dwp'):
                    if path.resolve() != path:
                        raise ValueError('split companion must not use symlinks: ' + str(path))
                    regular(path)
                    candidates.setdefault(name, set()).add(path)
    cache, result = {}, {}
    def inspect_split(path):
        if path not in cache:
            value = companion(dumper, path, time.monotonic() + 60, output_limit=limit)
            if value['status'] != 'available':
                raise ValueError('invalid split companion: ' + str(path))
            cache[path] = value
        return cache[path]
    packages = [path for name, paths in candidates.items() if name.endswith('.dwp') for path in paths]
    for image, (relative, found) in units.items():
        needed = {unit['dwo_id'] for unit in found}
        packed = [path for path in packages if needed <= set(inspect_split(path)['dwo_ids'])]
        if packed:
            if len({inspect_split(path)['sha256'] for path in packed}) != 1:
                raise ValueError('ambiguous split packages: ' + image)
            selected = [sorted(packed)[0]]
        else:
            selected = []
            for unit in found:
                matches = [path for path in candidates.get(Path(unit['name']).name, ())
                           if unit['dwo_id'] in inspect_split(path)['dwo_ids']]
                if not matches:
                    raise ValueError('missing matching split unit: ' + image + ': ' + unit['dwo_id'])
                if len({inspect_split(path)['sha256'] for path in matches}) != 1:
                    raise ValueError('ambiguous split units: ' + image + ': ' + unit['dwo_id'])
                selected.append(sorted(matches)[0])
        result[image] = {'file': str(relative) + '.dwp', 'dwo_ids': sorted(needed),
                         'inputs': [(path, inspect_split(path)['sha256']) for path in sorted(set(selected))]}
    return result, dumper


def retain_split(plan, destination, dumper):
    target = destination / relative_path(plan['file'])
    target.parent.mkdir(parents=True, exist_ok=True)
    for path, expected in plan['inputs']:
        if path.resolve() != path or file_identity(path, time.monotonic() + 60)[0]['sha256'] != expected:
            raise ValueError('split input changed before staging: ' + str(path))
    paths = [path for path, _ in plan['inputs']]
    if len(paths) == 1 and paths[0].suffix == '.dwp':
        shutil.copyfile(paths[0], target)
    else:
        packager = host_tool('llvm-dwp')
        if not packager:
            raise ValueError('split symbols require existing host llvm-dwp')
        if any(ord(character) < 32 for path in paths for character in str(path)):
            raise ValueError('split input path contains a control character')
        with tempfile.NamedTemporaryFile(mode='w', dir=destination, prefix='.soda-dwp-', delete=False) as file:
            response = Path(file.name)
            for path in paths:
                file.write(json.dumps(str(path), ensure_ascii=False) + '\n')
        try:
            subprocess.run([packager, '@' + str(response), '-o', str(target)], check=True, capture_output=True, timeout=120)
        finally:
            response.unlink(missing_ok=True)
    for path, expected in plan['inputs']:
        if path.resolve() != path or file_identity(path, time.monotonic() + 60)[0]['sha256'] != expected:
            raise ValueError('split input changed during staging: ' + str(path))
    actual = companion(dumper, target, time.monotonic() + 60, output_limit=64 * 1024 * 1024)
    if actual['status'] != 'available' or not set(plan['dwo_ids']) <= set(actual['dwo_ids']):
        raise ValueError('retained split package has missing unit identities')
    target.chmod(0o644)
    return {'file': plan['file'], 'sha256': actual['sha256'], 'dwo_ids': plan['dwo_ids'],
            'inputs': [{'name': path.name, 'sha256': expected} for path, expected in plan['inputs']]}


def relative_path(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or '..' in path.parts or str(path) != value:
        raise ValueError('invalid symbol bundle path')
    return Path(value)


def regular(path):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('symbol input must be a regular file: ' + str(path))


def crc32(path):
    regular(path)
    value = 0
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            value = zlib.crc32(block, value)
    return value


def inspect(path, tools, debug_only=False):
    regular(path)
    with path.open('rb') as file:
        magic = file.read(4)
    kind = 'elf' if magic == b'\x7fELF' else 'pe' if magic[:2] == b'MZ' else None
    if kind is None:
        return None
    arguments = ['--debug'] if kind == 'pe' and debug_only else []
    value = subprocess.check_output([str(tools / ('eagle-' + kind)), *arguments, str(path)], text=True, timeout=20)
    return json.loads(value)


def write_manifest(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as file:
        json.dump(value, file, sort_keys=True, indent=2)
        file.write('\n')
    path.chmod(0o644)


def refresh_eagle_manifest(runner, records):
    path = runner / 'share/eagle/build.json'
    if not path.exists():
        return
    if path.resolve() != path:
        raise ValueError('Eagle build manifest must not use symlinks')
    metadata = json.loads(path.read_text())
    for relative, record in records.items():
        if relative not in metadata['files']:
            continue
        if metadata['files'][relative] != record['input_sha256']:
            raise ValueError('Eagle build input does not match image: ' + relative)
        metadata['files'][relative] = record['image_sha256']
        if relative in metadata['symbols']:
            metadata['symbols'][relative]['sha256'] = record['image_sha256']
            if 'debug_file' in record:
                metadata['symbols'][relative].update(debug_info=False,
                    debuglink=Path(record['debug_file']).name,
                    debuglink_crc=record['debuglink_crc32'])
    temporary = path.with_name(path.name + ".next")
    write_manifest(temporary, metadata)
    temporary.replace(path)


def stage(runner, destination, tools, name, required=(), objcopy=None, debug_roots=()):
    runner = Path(runner).resolve(strict=True)
    destination = Path(destination).absolute()
    if destination.exists() or destination.resolve() != destination or destination.resolve() == runner or runner in destination.resolve().parents:
        raise ValueError('symbol destination must be new and outside the runner')
    if runner in destination.parents or destination.resolve() in runner.parents:
        raise ValueError('symbol destination overlaps the runner')
    metadata_path = runner / 'share/soda/symbols.json'
    for parent in (runner / 'share', runner / 'share/soda', metadata_path):
        if parent.is_symlink():
            raise ValueError('symbol metadata must not use symlinks')
    for parent in (runner / 'share', runner / 'share/soda'):
        if parent.exists() and not parent.is_dir():
            raise ValueError('symbol metadata parent must be a directory')
    if metadata_path.exists():
        raise ValueError('runner symbol manifest already exists')
    records, plans, pdb_plans = {}, [], {}
    for directory, names, files in os.walk(runner, followlinks=False):
        for filename in sorted(files):
            image = Path(directory) / filename
            if image.is_symlink():
                continue
            regular(image)
            if image.suffix in ('.debug', '.dwo', '.dwp', '.pdb'):
                continue
            metadata = inspect(image, tools)
            if metadata is None:
                continue
            relative = str(image.relative_to(runner))
            image_sha256 = digest(image)
            record = {'status': 'unavailable', 'input_sha256': image_sha256, 'image_sha256': image_sha256,
                      'identity': {key: metadata[key] for key in ('format', 'machine', 'timestamp', 'image_base', 'build_id', 'codeview') if key in metadata}}
            records[relative] = record
            if metadata.get('codeview'):
                identities = {(entry['guid'], entry['age']) for entry in metadata['codeview']}
                if len(identities) != 1:
                    raise ValueError('ambiguous PDB identities: ' + relative)
                names = {Path(entry['pdb']).name if entry['pdb'].startswith('/') else PureWindowsPath(entry['pdb']).name
                         for entry in metadata['codeview'] if entry['pdb']}
                if any(not name or name in ('.', '..') for name in names):
                    raise ValueError('invalid image PDB name: ' + relative)
                candidates = {path for name in names for path in (image.parent / name, image.parent / '.debug' / name)}
                found = [path for path in candidates if path.exists() or path.is_symlink()]
                record['pdb_status'] = 'unavailable'
                if found:
                    if len(found) != 1:
                        raise ValueError('ambiguous PDB companions: ' + relative)
                    pdb = found[0]
                    if pdb.resolve() != pdb:
                        raise ValueError('PDB companion must not use symlinks: ' + relative)
                    identity = pdb_identity(pdb)
                    if (identity['guid'], identity['age']) not in identities:
                        raise ValueError('PDB companion does not match image: ' + relative)
                    pdb_relative = str(pdb.relative_to(runner))
                    pdb_sha256 = digest(pdb)
                    pdb_plans[pdb_relative] = (pdb, pdb_sha256)
                    record.update(pdb_file=pdb_relative, pdb_sha256=pdb_sha256,
                                  pdb_identity=identity, pdb_status='matched', coverage='pdb-identity')
            if metadata.get('debug_info'):
                record['coverage'] = 'dwarf'
                debug_relative = image.parent.relative_to(runner) / '.debug' / (image.name + '.debug')
                plans.append((image, debug_relative, None, metadata))
            elif metadata.get('debuglink'):
                link = metadata['debuglink']
                if Path(link).name != link or link in ('.', '..') or '\\' in link:
                    raise ValueError('invalid image debuglink name: ' + relative)
                candidates = [image.parent / link, image.parent / '.debug' / link]
                found = [path for path in candidates if path.exists() or path.is_symlink()]
                if len(found) != 1:
                    raise ValueError('missing or ambiguous debug companion: ' + relative)
                debug = found[0]
                if debug.resolve() != debug or runner not in debug.parents or crc32(debug) != metadata['debuglink_crc']:
                    raise ValueError('debug companion does not match image: ' + relative)
                record['coverage'] = 'dwarf' if inspect(debug, tools, debug_only=True).get('debug_info') else 'symbol-only'
                plans.append((image, debug.relative_to(runner), debug, metadata))
    planned = {str(image.relative_to(runner)) for image, _, _, _ in plans if records[str(image.relative_to(runner))].get('coverage') == 'dwarf'}
    for value in required:
        relative_path(value)
        if value not in planned:
            raise ValueError('required image has no retained symbols: ' + value)
    if {str(relative) for _, relative, _, _ in plans} & set(pdb_plans):
        raise ValueError('PDB and GNU companions share an output path')
    if not plans and not pdb_plans:
        raise ValueError('runner has no debug symbols to retain')
    split, dumper = split_inputs(plans, runner, debug_roots)
    outputs = {str(relative) for _, relative, _, _ in plans} | set(pdb_plans)
    if any(plan['file'] in outputs for plan in split.values()):
        raise ValueError('split and other companions share an output path')
    destination.mkdir(parents=True)
    for relative, plan in split.items():
        records[relative]['split_dwarf'] = retain_split(plan, destination, dumper)
    llvm_objcopy = None
    for image, debug_relative, existing, before in plans:
        relative = str(image.relative_to(runner))
        record = records[relative]
        if digest(image) != record['image_sha256']:
            raise ValueError('runner changed during symbol staging: ' + relative)
        debug = destination / debug_relative
        debug.parent.mkdir(parents=True, exist_ok=True)
        if existing is not None:
            shutil.copyfile(existing, debug)
            if crc32(debug) != before['debuglink_crc']:
                raise ValueError('debug companion changed during symbol staging: ' + relative)
        else:
            if llvm_objcopy is None:
                if objcopy is None:
                    objcopy = host_tool('llvm-objcopy') or 'objcopy'
                version = subprocess.check_output([objcopy, '--version'], text=True, timeout=10)
                llvm_objcopy = version.splitlines()[0].lower().startswith('llvm')
            flags = [] if llvm_objcopy and before.get('format') != 'ELF' else ['--preserve-dates']
            subprocess.run([objcopy, *flags, '--only-keep-debug', str(image), str(debug)], check=True, capture_output=True, timeout=60)
            with tempfile.NamedTemporaryFile(dir=image.parent, prefix='.soda-symbols-', delete=False) as file:
                temporary = Path(file.name)
            try:
                subprocess.run([objcopy, *flags, '--remove-section=.gnu_debuglink', '--strip-unneeded',
                                '--add-gnu-debuglink=' + str(debug), str(image), str(temporary)],
                               check=True, capture_output=True, timeout=60)
                after = inspect(temporary, tools)
                for key in ('machine', 'timestamp', 'image_base', 'build_id', 'codeview', 'entry', 'entry_rva'):
                    if after.get(key) != before.get(key):
                        raise ValueError('stripping changed image ' + key + ': ' + relative)
                if after.get('debug_info') or after.get('debuglink') != debug.name or after.get('debuglink_crc') != crc32(debug):
                    raise ValueError('stripped image debuglink does not match: ' + relative)
                temporary.chmod(stat.S_IMODE(image.stat().st_mode))
                temporary.replace(image)
            finally:
                temporary.unlink(missing_ok=True)
        debug.chmod(0o644)
        record.update(status='retained', image_sha256=digest(image), debug_file=str(debug_relative),
                      debug_sha256=digest(debug), debuglink_crc32=crc32(debug))
    for relative, (pdb, expected) in pdb_plans.items():
        if digest(pdb) != expected:
            raise ValueError('PDB changed during symbol staging: ' + relative)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pdb, target)
        target.chmod(0o644)
        if digest(target) != expected:
            raise ValueError('PDB changed during symbol copy: ' + relative)
    for record in records.values():
        if 'pdb_file' in record:
            record['status'] = 'retained'
    retained = sum(record['status'] == 'retained' for record in records.values())
    manifest = {'schema': 1, 'component': name, 'images': records,
                'retained': retained, 'unavailable': len(records) - retained}
    write_manifest(destination / 'share/soda/symbols.json', manifest)
    write_manifest(metadata_path, manifest)
    for existing in {existing for _, _, existing, _ in plans if existing is not None}:
        existing.unlink()
    for pdb, _ in pdb_plans.values():
        pdb.unlink()
    for path in {path for plan in split.values() for path, _ in plan['inputs'] if runner in path.parents}:
        path.unlink()
    refresh_eagle_manifest(runner, records)
    verify(runner, destination, tools)
    return manifest


def verify(runner, bundle, tools):
    runner, bundle = Path(runner).resolve(strict=True), Path(bundle).resolve(strict=True)
    manifest_path = bundle / 'share/soda/symbols.json'
    for path in (manifest_path, runner / 'share/soda/symbols.json'):
        if path.resolve() != path:
            raise ValueError('symbol manifest must not use symlinks')
    regular(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    regular(runner / 'share/soda/symbols.json')
    if (runner / 'share/soda/symbols.json').read_bytes() != manifest_path.read_bytes():
        raise ValueError('runner and symbol bundle manifests differ')
    if type(manifest.get('schema')) is not int or manifest['schema'] != 1:
        raise ValueError('invalid symbol manifest schema')
    for relative, record in manifest['images'].items():
        image = runner / relative_path(relative)
        regular(image)
        if image.resolve() != image or digest(image) != record['image_sha256']:
            raise ValueError('symbol bundle does not match runner image: ' + relative)
        if record['status'] != 'retained':
            continue
        metadata = inspect(image, tools)
        if 'debug_file' in record:
            debug = bundle / relative_path(record['debug_file'])
            regular(debug)
            if debug.resolve() != debug or digest(debug) != record['debug_sha256'] or crc32(debug) != record['debuglink_crc32']:
                raise ValueError('symbol bundle companion does not match: ' + relative)
            if metadata.get('debuglink') != debug.name or metadata.get('debuglink_crc') != record['debuglink_crc32']:
                raise ValueError('runner debuglink does not match symbol bundle: ' + relative)
            units, _ = split_references(debug) if metadata.get('format') == 'ELF' else ([], None)
            expected_units = sorted({unit['dwo_id'] for unit in units})
            retained_units = record.get('split_dwarf', {}).get('dwo_ids', [])
            if expected_units != retained_units:
                raise ValueError('split manifest does not match debug image: ' + relative)
        if 'pdb_file' in record:
            pdb = bundle / relative_path(record['pdb_file'])
            regular(pdb)
            if pdb.resolve() != pdb or digest(pdb) != record['pdb_sha256'] or pdb_identity(pdb) != record['pdb_identity']:
                raise ValueError('symbol bundle PDB does not match: ' + relative)
            identity = record['pdb_identity']
            if not metadata.get('codeview') or any((entry['guid'], entry['age']) != (identity['guid'], identity['age']) for entry in metadata['codeview']):
                raise ValueError('runner CodeView does not match PDB: ' + relative)
        if 'split_dwarf' in record:
            split = record['split_dwarf']
            if not split['dwo_ids'] or split['file'] != record.get('debug_file', '') + '.dwp':
                raise ValueError('invalid split companion manifest: ' + relative)
            path = bundle / relative_path(split['file'])
            regular(path)
            if path.resolve() != path or digest(path) != split['sha256']:
                raise ValueError('split symbol bundle does not match: ' + relative)
            dumper = host_tool('llvm-dwarfdump')
            if not dumper:
                raise ValueError('split verification requires existing host llvm-dwarfdump')
            actual = companion(dumper, path, time.monotonic() + 60, output_limit=64 * 1024 * 1024)
            if actual['status'] != 'available' or not set(split['dwo_ids']) <= set(actual['dwo_ids']):
                raise ValueError('split symbol bundle has missing units: ' + relative)
        if 'debug_file' not in record and 'pdb_file' not in record:
            raise ValueError('retained image has no symbol companion: ' + relative)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('runner', type=Path)
    parser.add_argument('symbols', type=Path)
    parser.add_argument('--tools', required=True, type=Path)
    parser.add_argument('--name', default='soda')
    parser.add_argument('--require', action='append', default=[])
    parser.add_argument('--objcopy')
    parser.add_argument('--debug-root', action='append', default=[], type=Path)
    parser.add_argument('--verify', action='store_true')
    options = parser.parse_args()
    try:
        manifest = verify(options.runner, options.symbols, options.tools) if options.verify else stage(
            options.runner, options.symbols, options.tools, options.name, options.require, options.objcopy, options.debug_root)
        print(json.dumps({'component': manifest['component'], 'retained': manifest['retained'], 'unavailable': manifest['unavailable']}))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def digest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('build input must be a regular file')
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, 'rb') as file:
        result = hashlib.sha256()
        for block in iter(lambda: file.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()

def source_identity(source):
    source = Path(source).resolve(strict=True)
    try:
        revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], stderr=subprocess.DEVNULL, text=True, timeout=10).strip()
        dirty = bool(subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=normal'], text=True, timeout=10))
        names = subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', '.'], timeout=10).decode().split('\0')
        paths = [source / name for name in names if name]
    except (OSError, subprocess.SubprocessError):
        revision, dirty = None, None
        paths = [path for path in source.rglob('*') if '.git' not in path.relative_to(source).parts and '__pycache__' not in path.parts and path.suffix != '.pyc']
    files, links = {}, {}
    for path in sorted(set(paths)):
        if path.is_symlink():
            links[str(path.relative_to(source))] = os.readlink(path)
        elif path.is_file():
            files[str(path.relative_to(source))] = digest(path)
    payload = {'files': files, 'symlinks': links} if links else files
    tree = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'revision': revision, 'dirty': dirty, 'tree_sha256': tree, 'tree_format': 2 if links else 1,
            'files': files, 'symlinks': links}

def write(source, package, tools=()):
    package = Path(package).resolve(strict=True)
    destination = package / 'share/eagle/build.json'
    files = {str(path.relative_to(package)): digest(path) for path in sorted(package.rglob('*'))
             if path.is_file() and path != destination}
    symbols = {}
    for path in sorted((package / 'lib/eagle/native').glob('*')):
        if path.is_file():
            with path.open('rb') as file:
                magic = file.read(4)
            if magic[:2] == b'MZ' or magic == b'\x7fELF':
                helper = package / 'lib/eagle/native' / ('eagle-elf' if magic == b'\x7fELF' else 'eagle-pe')
                metadata = json.loads(subprocess.check_output([str(helper), str(path)], text=True, timeout=10))
                names = ('format', 'machine', 'timestamp', 'size', 'image_base', 'build_id', 'codeview', 'debug_info', 'debuglink', 'debuglink_crc')
                relative = str(path.relative_to(package))
                symbols[relative] = {'sha256': files[relative], **{key: metadata[key] for key in names if key in metadata}}
    versions = {tool: subprocess.check_output([tool, '--version'], text=True, timeout=10).splitlines()[0] for tool in tools}
    result = {'schema': 1, 'scope': 'Eagle package assembly; not the complete Wine runner',
              'source': source_identity(source), 'tools': versions, 'files': files, 'symbols': symbols}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result

def read_manifest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise ValueError('invalid build manifest file')
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, 'rb') as file:
        data = file.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('build manifest exceeds size limit')
    return json.loads(data), hashlib.sha256(data).hexdigest()

def source_fields(source):
    if not isinstance(source, dict):
        raise ValueError('invalid source identity')
    revision, dirty, tree = source.get('revision'), source.get('dirty'), source.get('tree_sha256')
    if (revision is not None and (not isinstance(revision, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', revision))) or (dirty is not None and type(dirty) is not bool) or not isinstance(tree, str) or not re.fullmatch(r'[0-9a-f]{64}', tree):
        raise ValueError('invalid source identity')
    return {'revision': revision, 'dirty': dirty, 'tree_sha256': tree}

def runner_identity(wine, observed=None):
    result = {}
    try:
        result['wine_sha256'] = observed or digest(wine)
        path = Path(wine).resolve().parent.parent / 'share/soda/build.json'
        if not path.exists():
            return dict(result, status='unavailable', reason='Soda runner build manifest is absent')
        metadata, result['manifest_sha256'] = read_manifest(path)
        if not isinstance(metadata, dict) or type(metadata.get('schema')) is not int or metadata['schema'] != 1:
            raise ValueError('unsupported runner build manifest')
        launcher, sources = metadata.get('wine'), metadata.get('source_identities')
        component = metadata.get('component')
        if not isinstance(component, str) or not re.fullmatch(r'[-A-Za-z0-9._+]{1,128}', component) or not isinstance(launcher, dict) or not isinstance(sources, dict) or len(sources) > 32 or metadata.get('source_status') not in ('recorded', 'unavailable'):
            raise ValueError('invalid runner source inventory')
        if any(not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', name) for name in sources):
            raise ValueError('invalid runner source label')
        expected = launcher.get('sha256')
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('invalid runner launcher identity')
        for key in ('files_sha256', 'sources_sha256'):
            value = metadata.get(key)
            if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
                raise ValueError('invalid runner inventory identity')
        result.update(status='matched' if result['wine_sha256'] == expected else 'mismatched',
                      component=component,
                      source_status=metadata['source_status'],
                      source_identities=[dict(label=name, **source_fields(value)) for name, value in sorted(sources.items())],
                      files_sha256=metadata['files_sha256'], sources_sha256=metadata['sources_sha256'],
                      verification='launcher digest only; source and file inventories are not rehashed')
        if 'assembly_source_identity' in metadata:
            result['assembly_source_identity'] = source_fields(metadata['assembly_source_identity'])
    except (OSError, ValueError) as error:
        result.update(status='invalid', reason=str(error))
    return result

def capture_identity(package, wine, collector):
    result = {}
    try:
        result['wine_sha256'] = digest(wine)
        result['collector_sha256'] = digest(collector)
        manifest = Path(package) / 'share/eagle/build.json'
        if not manifest.exists():
            return dict(result, status='unavailable', reason='Eagle build manifest is absent')
        metadata, result['manifest_sha256'] = read_manifest(manifest)
        if not isinstance(metadata, dict) or type(metadata.get('schema')) is not int or metadata['schema'] != 1:
            raise ValueError('unsupported Eagle build manifest')
        source, files = metadata.get('source'), metadata.get('files')
        if not isinstance(source, dict) or not isinstance(files, dict):
            raise ValueError('invalid Eagle build identity')
        identity = source_fields(source)
        relative = str(Path(collector).resolve().relative_to(Path(package).resolve()))
        expected = files.get(relative)
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('collector is absent from the Eagle build manifest')
        result.update(source_identity=identity,
                      status='matched' if expected == result['collector_sha256'] else 'mismatched',
                      verification='collector digest only; full package and Wine source provenance not revalidated')
    except (OSError, ValueError) as error:
        result.update(status='invalid', reason=str(error))
    return result


if __name__ == '__main__':
    write(sys.argv[1], sys.argv[2], sys.argv[3:])

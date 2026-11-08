import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import stat
import subprocess
import sys
import tarfile
import time
import zipfile


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/' + path]))


def download(run, prefix, destination):
    artifacts = api(f"actions/runs/{run['id']}/artifacts")['artifacts']
    artifact, = [item for item in artifacts if not item['expired'] and item['name'].startswith(prefix)
                 and (prefix != 'soda-' or item['name'].endswith('-x86_64'))]
    archive = destination.with_suffix('.zip')
    with archive.open('wb') as file:
        subprocess.run(['gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] +
                        f"/actions/artifacts/{artifact['id']}/zip"], stdout=file, check=True)
    with archive.open('rb') as file:
        assert 'sha256:' + hashlib.file_digest(file, 'sha256').hexdigest() == artifact['digest']
    with zipfile.ZipFile(archive) as package:
        assert all(not PurePosixPath(item.filename).is_absolute() and
                   '..' not in PurePosixPath(item.filename).parts and
                   not stat.S_ISLNK(item.external_attr >> 16) for item in package.infolist())
        package.extractall(destination)
    archive.unlink()
    return {'id': artifact['id'], 'name': artifact['name'], 'digest': artifact['digest']}


def prepare(work):
    source_id = os.environ['SOURCE_RUN']
    reference_id = os.environ['REFERENCE_RUN']
    assert re.fullmatch(r'[0-9]+', source_id) and re.fullmatch(r'[0-9]+', reference_id)
    source = api('actions/runs/' + source_id)
    reference = api('actions/runs/' + reference_id)
    for run in (source, reference):
        assert run['head_repository']['full_name'] == os.environ['GITHUB_REPOSITORY']
        assert run['head_branch'] == os.environ['GITHUB_REF_NAME']
        assert run['path'] == '.github/workflows/build-soda.yml' and run['status'] == 'completed'
    assert source['conclusion'] == 'success' and source['head_sha'] == reference['head_sha']
    jobs = api('actions/runs/' + reference_id + '/jobs')['jobs']
    assert next(job for job in jobs if job['name'] == 'composition-surface-reference')['conclusion'] == 'success'
    subprocess.run(['git', 'merge-base', '--is-ancestor', source['head_sha'], 'HEAD'], check=True)
    changed = subprocess.check_output(['git', 'diff', '--name-only', source['head_sha'], 'HEAD'], text=True).splitlines()
    assert set(changed) <= {'.github/workflows/build-soda.yml', '.github/soda-surface-diagnostics.py'}, changed
    provenance = {'scope': 'Wine surface diagnostics only; not native parity or Office qualification',
                  'compiled_source': source['head_sha'], 'diagnostic_source': os.environ['GITHUB_SHA'],
                  'source_run': source['id'], 'reference_run': reference['id'], 'changed_files': changed}
    provenance['runner_artifact'] = download(source, 'soda-', work / 'download')
    provenance['reference_artifact'] = download(reference, 'composition-surface-reference-', work / 'reference')
    archive, = (work / 'download').glob('*-x86_64.tar.xz')
    with archive.open('rb') as file:
        provenance['runner_archive_sha256'] = hashlib.file_digest(file, 'sha256').hexdigest()
    with tarfile.open(archive) as package:
        package.extractall(work / 'runner', filter='data')
    runner, = (work / 'runner').glob('soda-*-x86_64')
    root = runner / 'share/soda'
    metadata = json.loads((root / 'build.json').read_text())
    assert metadata['source_identities']['recipe']['revision'] == source['head_sha']
    for name in ('sources', 'files'):
        assert hashlib.sha256((root / (name + '.json')).read_bytes()).hexdigest() == metadata[name + '_sha256']
    sources = json.loads((root / 'sources.json').read_text())
    assert sources['sources']['recipe']['revision'] == source['head_sha']
    assert sources['patches'] == {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in Path('wine-tkg-userpatches').glob('*.mypatch')}
    assert (work / 'reference/composition-surface64.exe').is_file()
    (work / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    with open(os.environ['GITHUB_ENV'], 'a') as file:
        file.write('SURFACE_RUNNER=' + str(runner) + '\n')


def capture(command, env, destination, limit=64 * 1024 * 1024, timeout=120):
    total = saved = 0
    deadline = time.monotonic() + timeout
    timed_out = False
    with destination.with_suffix('.stdout').open('wb') as stdout, destination.with_suffix('.stderr').open('wb') as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=subprocess.PIPE)
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                if process.poll() is None:
                    process.kill()
                break
            ready, _, _ = select.select([process.stderr], [], [], 0.2)
            if not ready:
                if process.poll() is not None:
                    break
                continue
            data = os.read(process.stderr.fileno(), 65536)
            if not data:
                break
            total += len(data)
            chunk = data[:max(0, limit - saved)]
            stderr.write(chunk)
            saved += len(chunk)
        try:
            status = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            status = process.wait(timeout=10)
        process.stderr.close()
    return {'exit': status, 'timed_out': timed_out, 'stderr_bytes': total,
            'stderr_saved': saved, 'stderr_discarded': total - saved}


def collect(work, runner):
    results = []
    expected = (work / 'reference/composition-surface64.log').read_text(encoding='utf-8-sig').splitlines()
    expected = [line for line in expected if line.startswith('desktop=hybrid ')]
    assert len(expected) == 21
    for label, debug in (('plain', '-all'), ('traced', '-all,+timestamp,+win,+bitblt')):
        env = dict(os.environ, WINEPREFIX=str(work / ('prefix-' + label)), WINEARCH='win64', WINEDEBUG='-all',
                   WINEDLLOVERRIDES='dxgi,d3d11,d3d10core,windows.ui=b;mscoree,mshtml=;winemenubuilder.exe=d')
        try:
            with (work / (label + '-setup.log')).open('wb') as file:
                subprocess.run([str(runner / 'bin/wine'), 'wineboot', '-u'], env=env,
                               stdout=file, stderr=subprocess.STDOUT, check=True, timeout=90)
                subprocess.run([str(runner / 'bin/wine'), 'reg', 'add', r'HKCU\Software\Wine\Direct3D',
                                '/v', 'renderer', '/t', 'REG_SZ', '/d', 'gl', '/f'], env=env,
                               stdout=file, stderr=subprocess.STDOUT, check=True, timeout=30)
            env['WINEDEBUG'] = debug
            result = capture([str(runner / 'bin/wine'), str(work / 'reference/composition-surface64.exe')],
                             env, work / label)
            result.update(label=label, wine_debug=debug)
            lines = (work / (label + '.stdout')).read_text(errors='replace').splitlines()
            actual = [line for line in lines if line.startswith('desktop=hybrid ')]
            result['desktop_rows'] = len(actual)
            result['differences'] = [{'windows': before, 'soda': after}
                                     for before, after in zip(expected, actual) if before != after]
            results.append(result)
            (work / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            assert result['exit'] == 0 and not result['timed_out'] and len(actual) == 21, result
        finally:
            env['WINEDEBUG'] = '-all'
            subprocess.run([str(runner / 'bin/wineserver'), '-k'], env=env, check=False, timeout=30)
            subprocess.run([str(runner / 'bin/wineserver'), '-w'], env=env, check=True, timeout=30)


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare(Path(sys.argv[2]))
    elif sys.argv[1] == 'collect':
        collect(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise ValueError('Unknown surface diagnostic command')

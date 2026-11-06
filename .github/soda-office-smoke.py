import datetime
import gettext
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import zipfile


work, runner = (Path(value).resolve(strict=True) for value in sys.argv[1:])
output = work / 'office-results'
output.mkdir(exist_ok=False)
lock = threading.Lock()
result = {'installed': False, 'captures_collected': False, 'steps': [], 'launches': [],
          'scope': 'Fresh anonymous bottle using the published Bottles package and normal installer. Each launch restores the same stopped post-install prefix. X11 software rendering in CI; not the cpak supervisor or a signed-in user profile.'}
config = None
prefix = None
launcher_comparison = os.environ.get('OFFICE_LAUNCHER_COMPARISON') == 'true'


def record(stage, **fields):
    with lock:
        result.update(stage=stage, updated=datetime.datetime.now(datetime.timezone.utc).isoformat(), **fields)
        temporary = output / 'results.next.json'
        temporary.write_text(json.dumps(result, indent=2) + '\n')
        temporary.replace(output / 'results.json')
    print(stage, fields.get('activity', ''), flush=True)


def checked(stage, value):
    result['steps'].append({'name': stage, 'ok': value.ok, 'message': value.message})
    record(stage)
    if not value.ok:
        raise RuntimeError(value.message or (value.data or {}).get('message') or stage)
    return value


def stop_prefix():
    assert prefix is not None and prefix.resolve().is_relative_to(work / 'office-home')
    env = dict(os.environ, WINEPREFIX=str(prefix))
    statuses = []
    for argument in ('-k', '-w'):
        value = subprocess.run([str(runner / 'bin/wineserver'), argument], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        statuses.append({'argument': argument, 'exit': value.returncode,
                         'output': value.stdout.decode(errors='replace')[:1000]})
        if value.returncode not in ((0, 1) if argument == '-k' else (0,)):
            raise RuntimeError('Native wineserver cleanup failed: ' + str(statuses))
    return statuses


def restore_prefix():
    stop_prefix()
    assert not prefix.is_symlink() and prefix.resolve().is_relative_to(work / 'office-home')
    shutil.rmtree(prefix)
    shutil.copytree(baseline, prefix, symlinks=True)
    assert hives == {name: hashlib.sha256((prefix / name).read_bytes()).hexdigest() for name in hives}


def profile_controls():
    executable, = [item for item in manifest['Executables'] if item['file'] == 'WINWORD.EXE']
    target = prefix / 'drive_c' / executable['path']
    assert target.resolve(strict=True).is_relative_to(prefix / 'drive_c')
    eagle = str(runner / 'bin/eagle')
    reports = []
    diagnostics = work / 'office-profile-stderr'
    diagnostics.mkdir()
    checked('disable-tracing', manager.update_config(config, 'eagle_tracing', False, 'Parameters'))
    cases = [(profile, False) for profile in ('plain', 'plain-no-logs', 'crash', 'loader', 'com', 'wait', 'trace')]
    if launcher_comparison:
        launcher, = [path for path in target.parent.parent.rglob('*') if path.name.lower() == 'appvlp.exe']
        assert launcher.is_file() and not launcher.is_symlink() and launcher.resolve().is_relative_to(prefix / 'drive_c')
        record('office-launcher', office_launcher={'path': str(launcher.relative_to(prefix)),
                                                   'sha256': hashlib.sha256(launcher.read_bytes()).hexdigest()})
        cases = [(profile, wrapped) for profile in ('plain-no-logs', 'trace') for wrapped in (False, True)]
    for attempt in range(1, 4):
        for profile, wrapped in cases:
            restore_prefix()
            launched = launcher if wrapped else target
            application_args = [r'C:\office-reproduction.rtf']
            if wrapped:
                application_args.insert(0, 'C:\\' + target.relative_to(prefix / 'drive_c').as_posix().replace('/', '\\'))
            executor = WineExecutor(config=config, exec_path=str(launched), environment={}, program_winebridge=False)
            command = WineCommand(config, command='', environment=executor.environment, cwd=str(target.parent), minimal=True)
            assert Path(command.env['WINEPREFIX']).resolve() == prefix.resolve()
            if profile == 'plain-no-logs':
                command.env['WINEDEBUG'] = '-all'
            label = f'profile-{profile}-{attempt}' if not wrapped else f'profile-appvlp-{profile}-{attempt}'
            bundle = work / 'office-profile-sessions' / label
            destination = output / (label + '.log')
            before = set(logs.glob('*.session'))
            if profile in ('plain', 'plain-no-logs'):
                arguments = [str(runner / 'bin/wine'), str(launched), *application_args]
            elif profile == 'trace':
                arguments = [eagle, 'trace', '--wine', str(runner / 'bin/wine'), '--prefix', str(prefix),
                             '--logs', str(logs), '--cwd', str(target.parent), '--', str(launched), *application_args]
            else:
                arguments = [eagle, 'run', '--wine', str(runner / 'bin/wine'), '--prefix', str(prefix),
                             '--session', str(bundle), '--timeout', '60', '--profile', profile,
                             str(launched), *application_args]
            row = {'profile': profile, 'attempt': attempt, 'route': 'office launcher' if wrapped else 'direct target', 'winebridge': False,
                   'wine_debug': command.env.get('WINEDEBUG') if profile in ('plain', 'plain-no-logs') else '-all',
                   'prefix_restored': True, 'observation_seconds': 20, 'started': time.time()}
            reports.append(row)
            record('profile-started', profile_controls=reports)
            stderr = diagnostics / (label + '.stderr')
            with stderr.open('wb') as file:
                process = subprocess.Popen(arguments, env=command.env, cwd=target.parent,
                                           stdout=subprocess.DEVNULL, stderr=file)
                time.sleep(20)
                row['launcher_finished_before_stop'] = process.poll() is not None
                subprocess.run(['import', '-window', 'root', str(output / (label + '.png'))], check=True, timeout=15)
                with (output / (label + '-windows.log')).open('w') as windows:
                    subprocess.run(['xwininfo', '-root', '-tree'], stdout=windows, stderr=subprocess.STDOUT,
                                   check=True, timeout=10)
                row['stop_requested'] = time.time()
                closed = subprocess.run([str(runner / 'bin/wine'), 'taskkill', '/f', '/im', 'WINWORD.EXE'],
                                        env=command.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                row['owned_stop_exit'] = closed.returncode
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    if profile not in ('plain', 'plain-no-logs', 'trace'):
                        subprocess.run([eagle, 'control', str(bundle), 'detach'], check=True,
                                       stdout=subprocess.DEVNULL, stderr=file, timeout=10)
                        row['collector_stopped_after_observation'] = True
                    else:
                        stop_prefix()
                    process.wait(timeout=10)
                row['launcher_exit'] = process.returncode
            row['cleanup'] = stop_prefix()
            row['stderr_bytes'] = stderr.stat().st_size
            with stderr.open('rb') as file:
                row['stderr_sha256'] = hashlib.file_digest(file, 'sha256').hexdigest()
            if profile == 'trace':
                captured, = set(logs.glob('*.session')) - before
                generated = logs / (captured.stem + '.log')
                shutil.copyfile(generated, destination)
            elif profile not in ('plain', 'plain-no-logs'):
                subprocess.run([eagle, 'export', str(bundle), str(destination)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            if profile not in ('plain', 'plain-no-logs'):
                exported = json.loads(destination.read_text())
                assert exported['manifest']['completed'], label + ': incomplete capture'
                row['capture'] = destination.name
            office_log = label + '-office-metadata.json'
            subprocess.run([sys.executable, str(work / 'office-diagnostics.py'), str(prefix),
                            str(output / office_log), str(row['started'])], check=True, timeout=20)
            row['office_metadata'] = office_log
            record('profile-collected', profile_controls=reports)


try:
    record('load-bottles')
    for name, command in (('display', ['xwininfo', '-root']), ('vulkan', ['vulkaninfo', '--summary'])):
        with (output / (name + '.log')).open('w') as file:
            status = subprocess.run(command, stdout=file, stderr=subprocess.STDOUT, timeout=30).returncode
        record('check-' + name, **{name + '_exit': status})
        if status:
            raise RuntimeError(name + ' is unavailable in the test container')
    sys.path.insert(0, '/usr/share/bottles')
    gettext.install('com.usebottles.bottles')
    from bottles.backend.globals import Paths
    from bottles.backend.managers.manager import Manager
    from bottles.backend.managers.eagletracing import tracing_supported
    from bottles.backend.logger import Logger
    from bottles.backend.state import EventManager, Events
    from bottles.backend.utils.manager import ManagerUtils
    from bottles.backend.wine.executor import WineExecutor
    from bottles.backend.wine.winecommand import WineCommand

    manager = Manager(is_cli=True)
    Logger()
    manager.check_app_dirs()
    (Path(Paths.runners) / runner.name).symlink_to(runner, target_is_directory=True)
    record('prepare-components')
    manager.checks(install_latest=False, first_run=True)
    for event in (Events.ComponentsOrganizing, Events.DependenciesOrganizing, Events.InstallersOrganizing):
        EventManager.wait(event)
    components = manager.checks(install_latest=True, first_run=False)
    record('components-checked', components_ready=components.ok)
    created = checked('create-bottle', manager.create_bottle(
        name='OfficeStartup', environment='application', runner=runner.name,
        fn_logger=lambda text: record('create-bottle', activity=text)))
    config = created.data['config']
    prefix = Path(ManagerUtils.get_bottle_path(config))
    assert config.Runner == runner.name
    manifest = manager.installer_manager.get_installer('microsoft365enterprise')
    assert isinstance(manifest, dict)
    (output / 'installer.json').write_text(json.dumps(manifest, indent=2) + '\n')
    record('install-office')
    checked('install-office', manager.installer_manager.install(
        config, ('microsoft365enterprise', manager.supported_installers['microsoft365enterprise']),
        step_fn=lambda *args: record('install-office', activity=str(args)),
        activity_fn=lambda text: record('install-office', activity=text),
        log_fn=lambda text: print(text, flush=True)))
    files = {}
    for program in manifest['Executables']:
        path = prefix / 'drive_c' / program['path']
        assert path.is_file(), str(path)
        with path.open('rb') as file:
            files[program['file']] = {'bytes': path.stat().st_size,
                                      'sha256': hashlib.file_digest(file, 'sha256').hexdigest()}
    record('office-installed', installed=True, files=files, dependencies=config.Installed_Dependencies)
    assert config.Runner == runner.name and tracing_supported(config)
    checked('enable-tracing', manager.update_config(config, 'eagle_tracing', True, 'Parameters'))
    record('stop-installer-prefix', cleanup=stop_prefix())
    logs = prefix / 'logs/runs'
    document = prefix / 'drive_c/office-reproduction.rtf'
    document.write_text(r'{\rtf1\ansi\deff0 {\fonttbl {\f0 Arial;}}\f0\fs24 Office document opening test.\par Second paragraph.}', encoding='ascii')
    with zipfile.ZipFile(document.with_suffix('.docx'), 'w', zipfile.ZIP_DEFLATED) as package:
        package.writestr('[Content_Types].xml',
                         '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                         '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                         '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                         '</Types>')
        package.writestr('_rels/.rels',
                         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                         '</Relationships>')
        package.writestr('word/document.xml',
                         '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                         '<w:p><w:r><w:t>Office document opening test.</w:t></w:r></w:p>'
                         '<w:p><w:r><w:t>Second paragraph.</w:t></w:r></w:p>'
                         '</w:body></w:document>')
    record('prepare-document', documents={kind: hashlib.sha256(document.with_suffix('.' + kind).read_bytes()).hexdigest()
                                         for kind in ('rtf', 'docx')})
    baseline = work / 'office-initial-prefix'
    shutil.copytree(prefix, baseline, symlinks=True)
    hives = {name: hashlib.sha256((baseline / name).read_bytes()).hexdigest()
             for name in ('system.reg', 'user.reg', 'userdef.reg')}
    record('prefix-baseline', registry_baseline=hives)
    launches = (('WINWORD.EXE', False, False), ('WINWORD.EXE', True, False),
                ('WINWORD.EXE', False, 'rtf'), ('WINWORD.EXE', True, 'rtf'),
                ('WINWORD.EXE', False, 'docx'), ('WINWORD.EXE', True, 'docx'),
                ('EXCEL.EXE', False, False), ('EXCEL.EXE', True, False))
    if launcher_comparison:
        launches = ()
    for executable, tracing, opening in launches:
        restore_prefix()
        checked('set-tracing', manager.update_config(config, 'eagle_tracing', tracing, 'Parameters'))
        program, = [item for item in config.External_Programs.values() if item['executable'] == executable]
        program = dict(program, winebridge=False)
        if opening:
            program.update(arguments='"C:\\office-reproduction.' + opening + '"', arguments_enabled=True)
        before = set(logs.glob('*.log'))
        sessions = set(logs.glob('*.session'))
        label = f'{len(result["launches"]) + 1}-{executable}-' + ('traced' if tracing else 'plain')
        launch = {'executable': executable, 'tracing': tracing, 'opening_document': bool(opening),
                  'document_format': opening or None,
                  'winebridge': False,
                  'prefix_restored': True, 'started': time.time(),
                  'stop_reason': 'Own app terminated after the observation deadline, then its prefix stopped'}
        result['launches'].append(launch)
        record('launch-' + executable)
        def run_program(program=program, launch=launch):
            try:
                value = WineExecutor.run_program(config, program)
                with lock:
                    launch['launcher_ok'] = value.ok
                    launch['launcher_message'] = value.message
                    launch['launcher_finished'] = time.time()
            except Exception as error:
                with lock:
                    launch['launcher_error'] = type(error).__name__ + ': ' + str(error)
        thread = threading.Thread(target=run_program, daemon=True)
        thread.start()
        time.sleep(45)
        with (output / (label + '-windows.log')).open('w') as file:
            subprocess.run(['xwininfo', '-root', '-tree'], stdout=file, stderr=subprocess.STDOUT,
                           check=True, timeout=10)
        subprocess.run(['import', '-window', 'root', str(output / (label + '.png'))],
                       check=True, timeout=15)
        launch['launcher_finished_before_stop'] = not thread.is_alive()
        launch['stop_requested'] = time.time()
        command = WineCommand(config, command='taskkill', minimal=True)
        assert Path(command.env['WINEPREFIX']).resolve() == prefix.resolve()
        closed = subprocess.run([str(runner / 'bin/wine'), 'taskkill', '/f', '/im', executable],
                                env=command.env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=30)
        launch['app_stop'] = {'exit': closed.returncode,
                              'output': closed.stdout.decode(errors='replace')[:2000]}
        thread.join(timeout=10)
        launch['prefix_cleanup'] = stop_prefix()
        thread.join(timeout=30)
        launch['launcher_pending'] = thread.is_alive()
        launch['cleanup_completed'] = time.time()
        with (output / (label + '-after-stop-windows.log')).open('w') as file:
            subprocess.run(['xwininfo', '-root', '-tree'], stdout=file, stderr=subprocess.STDOUT,
                           check=True, timeout=10)
        saved = []
        for path in logs.glob('*.log'):
            if path not in before:
                shutil.copyfile(path, output / (label + '-' + path.name))
                saved.append(path.name)
        launch['logs'] = saved
        diagnostics = []
        for session in set(logs.glob('*.session')) - sessions:
            path = session / 'stderr.log'
            if path.is_file():
                data = path.read_bytes()
                assert len(data) <= 1024 * 1024
                name = label + '-' + session.stem + '-stderr.log'
                (output / name).write_bytes(data)
                diagnostics.append({'file': name, 'bytes': len(data),
                                    'sha256': hashlib.sha256(data).hexdigest()})
        launch['stderr'] = diagnostics
        office_log = label + '-office-metadata.json'
        subprocess.run([sys.executable, str(work / 'office-diagnostics.py'), str(prefix),
                        str(output / office_log), str(launch['started'])], check=True, timeout=20)
        launch['office_metadata'] = office_log
        assert saved or not tracing, executable + ': no Eagle log collected'
        record('captured-' + executable)
        assert not launch['launcher_pending'], executable + ': launcher did not finish after cleanup'
    profile_controls()
    record('finished', captures_collected=True)
except Exception as error:
    record('failed', error=type(error).__name__ + ': ' + str(error))
finally:
    if config is not None:
        try:
            stop_prefix()
        except Exception as error:
            record('cleanup-failed', cleanup_error=type(error).__name__ + ': ' + str(error))
raise SystemExit(0 if result['installed'] and result['captures_collected'] and 'cleanup_error' not in result else 1)

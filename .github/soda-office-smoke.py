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


work, runner = (Path(value).resolve(strict=True) for value in sys.argv[1:])
output = work / 'office-results'
output.mkdir(exist_ok=False)
lock = threading.Lock()
result = {'installed': False, 'captures_collected': False, 'steps': [], 'launches': [],
          'scope': 'Fresh anonymous bottle using the published Bottles package and normal installer. Sequential launches share the installed prefix; first-run state can change between launches. X11 software rendering in CI; not the cpak supervisor or a signed-in user profile.'}
config = None
prefix = None


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
    for executable, tracing in (('WINWORD.EXE', True), ('EXCEL.EXE', True),
                                ('EXCEL.EXE', False), ('EXCEL.EXE', True),
                                ('EXCEL.EXE', False)):
        checked('set-tracing', manager.update_config(config, 'eagle_tracing', tracing, 'Parameters'))
        program, = [item for item in config.External_Programs.values() if item['executable'] == executable]
        before = set(logs.glob('*.log'))
        sessions = set(logs.glob('*.session'))
        label = f'{len(result["launches"]) + 1}-{executable}-' + ('traced' if tracing else 'plain')
        launch = {'executable': executable, 'tracing': tracing, 'started': time.time(),
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
        assert saved or not tracing, executable + ': no Eagle log collected'
        record('captured-' + executable)
        assert not launch['launcher_pending'], executable + ': launcher did not finish after cleanup'
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

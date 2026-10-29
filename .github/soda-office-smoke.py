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
          'scope': 'Fresh anonymous bottle using the published Bottles package and normal installer. X11 software rendering in CI; not the cpak supervisor or a signed-in user profile.'}
config = None


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


try:
    record('load-bottles')
    sys.path.insert(0, '/usr/share/bottles')
    gettext.install('com.usebottles.bottles')
    from bottles.backend.globals import Paths
    from bottles.backend.managers.manager import Manager
    from bottles.backend.managers.eagletracing import tracing_supported
    from bottles.backend.utils.manager import ManagerUtils
    from bottles.backend.wine.executor import WineExecutor
    from bottles.backend.wine.wineserver import WineServer

    manager = Manager(is_cli=True)
    manager.check_app_dirs()
    (Path(Paths.runners) / runner.name).symlink_to(runner, target_is_directory=True)
    record('prepare-components')
    checked('components', manager.checks(install_latest=True, first_run=True))
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
    logs = prefix / 'logs/runs'
    for executable in ('WINWORD.EXE', 'EXCEL.EXE'):
        program, = [item for item in config.External_Programs.values() if item['executable'] == executable]
        before = set(logs.glob('*.log'))
        launch = {'executable': executable, 'stop_reason': 'Own prefix stopped after the observation deadline'}
        result['launches'].append(launch)
        record('launch-' + executable)
        def run_program(program=program, launch=launch):
            try:
                value = WineExecutor.run_program(config, program)
                with lock:
                    launch['launcher_ok'] = value.ok
                    launch['launcher_message'] = value.message
            except Exception as error:
                with lock:
                    launch['launcher_error'] = type(error).__name__ + ': ' + str(error)
        thread = threading.Thread(target=run_program, daemon=True)
        thread.start()
        time.sleep(45)
        with (output / (executable + '-windows.log')).open('w') as file:
            subprocess.run(['xwininfo', '-root', '-tree'], stdout=file, stderr=subprocess.STDOUT,
                           check=True, timeout=10)
        subprocess.run(['import', '-window', 'root', str(output / (executable + '.png'))],
                       check=True, timeout=15)
        WineServer(config).kill()
        thread.join(timeout=30)
        launch['launcher_pending'] = thread.is_alive()
        saved = []
        for path in logs.glob('*.log'):
            if path not in before:
                shutil.copyfile(path, output / (executable + '-' + path.name))
                saved.append(path.name)
        launch['logs'] = saved
        assert saved, executable + ': no Eagle log collected'
        record('captured-' + executable)
    record('finished', captures_collected=True)
except Exception as error:
    record('failed', error=type(error).__name__ + ': ' + str(error))
finally:
    if config is not None:
        try:
            WineServer(config).kill()
        except Exception as error:
            record('cleanup-failed', cleanup_error=type(error).__name__ + ': ' + str(error))
raise SystemExit(0 if result['installed'] and result['captures_collected'] else 1)

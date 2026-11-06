import datetime
import gettext
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


work, runner = (Path(value).resolve(strict=True) for value in sys.argv[1:])
output = work / 'results'
output.mkdir(exist_ok=True)
result = {'installed': False, 'scope': 'Anonymous ARM64 installation using published Soda and the normal Bottles installer'}
prefix = None
started = time.time()


def record(stage, **fields):
    result.update(stage=stage, updated=datetime.datetime.now(datetime.timezone.utc).isoformat(), **fields)
    (output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(stage, flush=True)


def checked(stage, value):
    record(stage)
    if not value.ok:
        raise RuntimeError(value.message or (value.data or {}).get('message') or stage)
    return value


try:
    sys.path.insert(0, '/usr/share/bottles')
    gettext.install('com.usebottles.bottles')
    from bottles.backend.globals import Paths
    from bottles.backend.managers.manager import Manager
    from bottles.backend.logger import Logger
    from bottles.backend.state import EventManager, Events
    from bottles.backend.utils.manager import ManagerUtils

    manager = Manager(is_cli=True)
    Logger()
    manager.check_app_dirs()
    (Path(Paths.runners) / runner.name).symlink_to(runner, target_is_directory=True)
    manager.checks(install_latest=False, first_run=True)
    for event in (Events.ComponentsOrganizing, Events.DependenciesOrganizing, Events.InstallersOrganizing):
        EventManager.wait(event)
    checked('components', manager.checks(install_latest=True, first_run=False))
    created = checked('create-bottle', manager.create_bottle(
        name='OfficeArmInstall', environment='application', runner=runner.name))
    config = created.data['config']
    prefix = Path(ManagerUtils.get_bottle_path(config))
    assert config.Runner == runner.name
    checked('loader-diagnostics', manager.update_config(
        config, 'WINEDEBUG', 'fixme-all,+module,+loaddll', 'Environment_Variables'))
    installer = 'microsoft365enterprise'
    manifest = manager.installer_manager.get_installer(installer)
    assert isinstance(manifest, dict)
    (output / 'installer.json').write_text(json.dumps(manifest, indent=2) + '\n')
    checked('install-office', manager.installer_manager.install(
        config, (installer, manager.supported_installers[installer]),
        log_fn=lambda text: print(text, flush=True)))
    files = {}
    for entry in manifest['Executables']:
        path = prefix / 'drive_c' / entry['path']
        assert path.is_file()
        files[entry['file']] = hashlib.sha256(path.read_bytes()).hexdigest()
    record('installed', installed=True, files=files)
except Exception as error:
    record('failed', error=type(error).__name__ + ': ' + str(error))
finally:
    if prefix is not None:
        assert prefix.resolve().is_relative_to(work / 'office-home')
        identities = []
        for path in (prefix / 'drive_c').rglob('*'):
            if path.name.casefold() not in ('offreg.dll', 'officeclicktorun.exe') or not path.is_file():
                continue
            with path.open('rb') as file:
                header = file.read(64)
                machine = None
                if len(header) == 64 and header[:2] == b'MZ':
                    file.seek(int.from_bytes(header[60:64], 'little'))
                    pe = file.read(6)
                    if pe[:4] == b'PE\0\0':
                        machine = int.from_bytes(pe[4:6], 'little')
                file.seek(0)
                digest = hashlib.file_digest(file, 'sha256').hexdigest()
            identities.append({'path': str(path.relative_to(prefix)), 'machine': machine,
                               'bytes': path.stat().st_size, 'sha256': digest})
        record('module-identities', modules=identities)
        status = subprocess.run([sys.executable, str(work / 'office-diagnostics.py'), str(prefix),
                                 str(output / 'office-metadata.json'), str(started)], timeout=30)
        if status.returncode:
            record('diagnostics-failed', diagnostics_exit=status.returncode)
        for argument in ('-k', '-w'):
            stopped = subprocess.run([str(runner / 'bin/wineserver'), argument],
                                     env=dict(os.environ, WINEPREFIX=str(prefix)), timeout=30)
            if stopped.returncode not in ((0, 1) if argument == '-k' else (0,)):
                record('cleanup-failed', cleanup_exit=stopped.returncode)
raise SystemExit(0 if result['installed'] and 'cleanup_exit' not in result and 'diagnostics_exit' not in result else 1)

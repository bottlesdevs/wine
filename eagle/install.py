import hashlib
import json
from pathlib import Path
import platform
import sys

runner = Path(sys.argv[1]).resolve(strict=True)
architectures = ('aarch64',) if platform.machine() == 'aarch64' else ('i386', 'x86_64')
identities = {}
for architecture in architectures:
    for module in ('combase', 'dwrite', 'd2d1', 'kernelbase', 'ntdll'):
        path = runner / f'lib/wine/{architecture}-windows/{module}.dll'
        data = path.read_bytes()
        if b'EAGLE/1' not in data:
            raise ValueError(f'{architecture} {module} does not include Eagle providers')
        if module == 'd2d1' and any(marker not in data for marker in (b'd2d.end_draw', b'd2d.flush')):
            raise ValueError(f'{architecture} d2d1 does not include Eagle draw results')
        if module == 'kernelbase' and any(marker not in data for marker in (b'loader.LoadLibraryExW', b'loader.GetProcAddress', b'loader.FreeLibrary', b'loader.LoadPackagedLibrary', b'__wine_eagle_loader_result')):
            raise ValueError(f'{architecture} kernelbase does not include Eagle loader results')
        if module == 'ntdll' and any(marker not in data for marker in (b'loader.LdrLoadDll', b'loader.LdrGetProcedureAddress', b'loader.LdrUnloadDll', b'loader.DependencyFailure')):
            raise ValueError(f'{architecture} ntdll does not include Eagle native loader results')
        identities[f'{architecture}/{module}'] = hashlib.sha256(data).hexdigest()
    path = runner / f'lib/wine/{architecture}-windows/kernel32.dll'
    data = path.read_bytes()
    if any(marker not in data for marker in (b'__wine_eagle_loader_result', b'loader.GetProcAddress')):
        raise ValueError(f'{architecture} kernel32 does not include Eagle loader results')
    identities[f'{architecture}/kernel32'] = hashlib.sha256(data).hexdigest()
    path = runner / f'lib/wine/{architecture}-windows/windows.security.authentication.onlineid.dll'
    data = path.read_bytes()
    if any(marker not in data for marker in (b'identity.stage', b'identity.native.stage', b'EAGLE/1')):
        raise ValueError(f'{architecture} onlineid does not include Eagle identity stages')
    identities[f'{architecture}/windows.security.authentication.onlineid'] = hashlib.sha256(data).hexdigest()
manifest = {
    'schema': 1,
    'tracing': 1,
    'profiles': {name: ['32', '64'] for name in ('winrt', 'dwrite', 'd2d', 'loader', 'com', 'wait')},
    'scopes': {
        'loader': 'Win32 library/export outcomes, native LdrLoadDll/LdrGetProcedureAddress/LdrUnloadDll and internal dependency-load failures; basenames only; independent 4096-event Win32 and native budgets per process; process-detach unloads excluded',
        'd2d': 'EndDraw/Flush HRESULT and error tags; 4096 events per process, then one budget marker',
        'com': 'activation, class object, initialization/uninitialization, activation-only QueryInterface',
        'wait': 'observed KernelBase mutex handles within each process; partial coverage',
    },
    'provider_sha256': identities,
    'identity_stages': {'schema': 1, 'provider': 1, 'transports': ['host-bridge', 'native'], 'native_flow': True},
}
destination = runner / 'share/eagle/providers.json'
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(manifest, indent=2) + '\n')

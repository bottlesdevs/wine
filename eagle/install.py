import hashlib
import json
from pathlib import Path
import platform
import sys

runner = Path(sys.argv[1]).resolve(strict=True)
architectures = ('aarch64',) if platform.machine() == 'aarch64' else ('i386', 'x86_64')
identities = {}
for architecture in architectures:
    for module in ('combase', 'dwrite', 'kernelbase'):
        path = runner / f'lib/wine/{architecture}-windows/{module}.dll'
        data = path.read_bytes()
        if b'EAGLE/1' not in data:
            raise ValueError(f'{architecture} {module} does not include Eagle providers')
        identities[f'{architecture}/{module}'] = hashlib.sha256(data).hexdigest()
    path = runner / f'lib/wine/{architecture}-windows/windows.security.authentication.onlineid.dll'
    data = path.read_bytes()
    if b'identity.stage' not in data or b'EAGLE/1' not in data:
        raise ValueError(f'{architecture} onlineid does not include Eagle identity stages')
    identities[f'{architecture}/windows.security.authentication.onlineid'] = hashlib.sha256(data).hexdigest()
manifest = {
    'schema': 1,
    'tracing': 1,
    'profiles': {name: ['32', '64'] for name in ('winrt', 'dwrite', 'com', 'wait')},
    'scopes': {
        'com': 'activation, class object, initialization/uninitialization, activation-only QueryInterface',
        'wait': 'observed KernelBase mutex handles within each process; partial coverage',
    },
    'provider_sha256': identities,
    'identity_stages': {'schema': 1, 'provider': 1, 'transports': ['host-bridge'], 'native_flow': False},
}
destination = runner / 'share/eagle/providers.json'
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(manifest, indent=2) + '\n')

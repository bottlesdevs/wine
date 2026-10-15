import re

OPERATIONS = {2: 'authorize', 3: 'get_token', 5: 'list_accounts'}
STAGES = {1: 'begin', 2: 'transport', 3: 'response', 4: 'complete'}
NATIVE_STAGES = {1: 'begin', 3: 'response', 4: 'complete', 5: 'cache', 6: 'request', 7: 'prompt', 8: 'persist'}


def decode(payload):
    fields = {'provider', 'event', 'hresult', 'a', 'b', 'c', 'd', 'subject', 'iid', 'caller'}
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError('invalid identity stage fields')
    if type(payload['provider']) is not int or payload['provider'] != 1 or payload['event'] not in ('identity.stage', 'identity.native.stage'):
        raise ValueError('invalid identity stage provider')
    if any(type(payload[name]) is not int for name in ('a', 'b', 'c', 'd')):
        raise ValueError('invalid identity stage values')
    native = payload['event'] == 'identity.native.stage'
    stages = NATIVE_STAGES if native else STAGES
    if payload['a'] not in OPERATIONS or payload['b'] != (2 if native else 1) or not 0 < payload['c'] <= 0xffffffff or payload['d'] not in stages:
        raise ValueError('unsupported identity stage values')
    if payload['subject'] != '' or payload['iid'] != '':
        raise ValueError('identity stages cannot contain subject or interface data')
    if not isinstance(payload['hresult'], str) or not re.fullmatch(r'0x[0-9a-fA-F]{8}', payload['hresult']):
        raise ValueError('invalid identity stage result')
    if not isinstance(payload['caller'], str) or not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{1,16}', payload['caller']):
        raise ValueError('invalid identity stage caller')
    return {'provider': 1, 'event': 'identity.stage', 'hresult': payload['hresult'].lower(),
            'request_id': payload['c'], 'operation': OPERATIONS[payload['a']],
            'transport': 'native' if native else 'host-bridge', 'stage': stages[payload['d']], 'caller': payload['caller']}

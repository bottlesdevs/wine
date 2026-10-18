import json
from pathlib import Path
from types import SimpleNamespace
from .runtime import run_tool

def merge_suggestions(suggestions, plan):
    command = Path(__file__).resolve().parents[1] / 'native/eagle-analysis'
    result = run_tool([str(command)], input=json.dumps({'operation': 'merge', 'suggestions': suggestions, 'intel': plan}), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

def recommendations(details, metadata, is_net, dpi_aware, shipping, plan):
    command = Path(__file__).resolve().parents[1] / 'native/eagle-analysis'
    request = dict(operation='recommend', details=details, metadata=metadata, is_net=is_net, dpi_aware=dpi_aware, ue_shipping_exe=shipping, intel=plan)
    result = run_tool([str(command)], input=json.dumps(request), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

def extract_asar(path, output):
    command = Path(__file__).resolve().parents[1] / 'native/eagle-analysis'
    result = run_tool([str(command)], input=json.dumps({'operation': 'asar', 'path': str(path), 'output': str(output)}), capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

def discover(path, details):
    command = Path(__file__).resolve().parents[1] / 'native/eagle-analysis'
    result = run_tool([str(command)], input=json.dumps({'operation': 'discover', 'path': str(path), 'details': details}), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

def yara_insights(rows, details, source):
    command = Path(__file__).resolve().parents[1] / 'native/eagle-analysis'
    request = dict(operation='yara-insights', matches=rows, details=details, source=source)
    result = run_tool([str(command)], input=json.dumps(request), capture_output=True, text=True, timeout=30)
    if result.returncode: raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

def pe_insights(structure, details, metadata, basename, compilers, packers, mapping):
    command = Path(__file__).resolve().parents[1] / 'native/eagle-analysis'
    request = dict(operation='pe-insights', structure=structure, details=details, metadata=metadata, basename=basename, compilers=compilers, packers=packers, mapping=mapping)
    result = run_tool([str(command)], input=json.dumps(request), capture_output=True, text=True, timeout=30)
    if result.returncode: raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

def steam_appid(path):
    command = Path(__file__).resolve().parents[1] / 'native/eagle-analysis'
    result = run_tool([str(command)], input=json.dumps(dict(operation='steam-appid', path=str(path))), capture_output=True, text=True, timeout=30)
    if result.returncode: raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

def artifact_hashes(path, imports=''):
    command = Path(__file__).resolve().parents[1] / 'native/eagle-analysis'
    request = dict(operation='artifact-hashes', path=str(path), imports=imports)
    result = run_tool([str(command)], input=json.dumps(request), capture_output=True, text=True, timeout=30)
    if result.returncode: raise ValueError(result.stderr.strip())
    return json.loads(result.stdout)

class PE:
    def __init__(self, path):
        command = Path(__file__).resolve().parents[1] / "native/eagle-pe"
        result = run_tool([str(command), str(path)], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError(result.stderr.strip())
        self.data = json.loads(result.stdout)

    def get_imphash(self):
        return artifact_hashes('', self.data['imphash_material'])['imphash']

class Rules:
    def __init__(self, rules_path):
        self.path = rules_path
        self.command = Path(__file__).resolve().parents[1] / "native/eagle-yara"
        if not self.command.is_file():
            raise FileNotFoundError("native rule scanner is not built")

    def rows(self, path, timeout=30):
        result = run_tool([str(self.command), self.path, str(path), str(timeout)], capture_output=True, text=True, timeout=timeout + 5)
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        return json.loads(result.stdout)["matches"]

    def match(self, path, timeout=30):
        matches = []
        for row in self.rows(path, timeout):
            strings = [SimpleNamespace(identifier=item["identifier"], instances=[SimpleNamespace(matched_data=bytes.fromhex(item["hex"]))]) for item in row["strings"]]
            matches.append(SimpleNamespace(rule=row["rule"], meta=row["meta"], strings=strings))
        return matches

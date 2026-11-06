import collections
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(os.environ['EAGLE_TEST_ROOT'])
PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
WINE = os.environ['EAGLE_TEST_WINE']
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from session import capture, read_bundle, windows_path


class WininetTLS(unittest.TestCase):
    def test_loopback_certificate_chain_with_and_without_providers(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            directory = Path(directory)
            class RevocationHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path != '/fixture.crl':
                        self.send_error(404)
                        return
                    body = (directory / 'fixture.crl').read_bytes()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/pkix-crl')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *args):
                    pass

            revocation = http.server.ThreadingHTTPServer(('127.0.0.1', 0), RevocationHandler)
            self.addCleanup(revocation.server_close)
            (directory / 'index').write_text('')
            (directory / 'crlnumber').write_text('01\n')
            (directory / 'ca.conf').write_text('[ca]\ndefault_ca=fixture\n[fixture]\ndatabase=index\ncertificate=ca.pem\nprivate_key=ca.key\ncrlnumber=crlnumber\ndefault_md=sha256\ndefault_crl_days=1\n')
            commands = [
                ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Eagle owned root',
                 '-keyout', 'ca.key', '-out', 'ca.pem', '-addext', 'basicConstraints=critical,CA:TRUE',
                 '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
                ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', 'server.key', '-out', 'server.csr'],
                ['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
                 '-days', '1', '-out', 'server.pem', '-extfile', 'server.ext'],
                ['x509', '-in', 'ca.pem', '-outform', 'DER', '-out', 'ca.der'],
                ['ca', '-gencrl', '-config', 'ca.conf', '-out', 'fixture.pem'],
                ['crl', '-in', 'fixture.pem', '-outform', 'DER', '-out', 'fixture.crl'],
            ]
            (directory / 'server.ext').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n'
                                                f'crlDistributionPoints=URI:http://127.0.0.1:{revocation.server_port}/fixture.crl\n')
            for command in commands:
                subprocess.run(['openssl', *command], cwd=directory, check=True, capture_output=True, timeout=30)
            with (directory / 'server.pem').open('ab') as chain:
                chain.write((directory / 'ca.pem').read_bytes())
            revocation_thread = threading.Thread(target=revocation.serve_forever, daemon=True)
            revocation_thread.start()
            self.addCleanup(revocation_thread.join, 5)
            self.addCleanup(revocation.shutdown)
            requests = []
            lock = threading.Lock()
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    with lock:
                        requests.append(self.connection.version())
                    body = b'Eagle loopback TLS\n'
                    self.send_response(200 if self.path == '/owned-fixture' else 404)
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *args):
                    pass

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(directory / 'server.pem', directory / 'server.key')
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            rows = []
            try:
                for bits in (32, 64):
                    for profile in ('plain', 'crash', 'loader', 'trace'):
                        with self.subTest(bits=bits, profile=profile):
                            root = ROOT / f'wininet-tls-{bits}-{profile}'
                            with lock:
                                before = len(requests)
                            arguments = [str(server.server_port), windows_path(directory / 'ca.der', ROOT / 'prefix')]
                            if profile == 'plain':
                                process = subprocess.run([WINE, str(ROOT / f'wininet-tls{bits}.exe'), *arguments],
                                                         env=dict(os.environ, WINEPREFIX=str(ROOT / 'prefix'), WINEDEBUG='-all'),
                                                         capture_output=True, timeout=60)
                                (ROOT / f'wininet-tls-{bits}-plain.stderr').write_bytes(process.stderr)
                                manifest, events = None, []
                                exits = [process.returncode]
                            else:
                                capture(WINE, ROOT / 'prefix', root, target=ROOT / f'wininet-tls{bits}.exe',
                                        arguments=arguments, profile=profile, timeout=60)
                                manifest, events = read_bundle(root)
                                exits = [e['code'] for e in events if e['kind'] == 'process_exit']
                            with lock:
                                received = requests[before:]
                            faults = [e for e in events if e['kind'] == 'exception' and not e['first_chance']]
                            rows.append({'bits': bits, 'profile': profile, 'requests': len(received),
                                         'tls_versions': dict(collections.Counter(received)), 'exits': exits,
                                         'terminal_exceptions': len(faults),
                                         'completed': manifest['completed'] if manifest else None,
                                         'dropped_events': manifest['dropped_events'] if manifest else None})
                            (ROOT / 'wininet-tls-results.log').write_text(json.dumps(rows, indent=2) + '\n')
                            if manifest:
                                self.assertTrue(manifest['completed'])
                                self.assertEqual(manifest['dropped_events'], 0)
                            self.assertEqual(exits, [0])
                            self.assertEqual(faults, [])
                            self.assertEqual(len(received), 16)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main(verbosity=2)

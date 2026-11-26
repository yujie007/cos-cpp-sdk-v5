"""Exercise both HTTPS send paths and a public COS PUT against a local TLS server."""
import argparse
import datetime as dt
import hashlib
import http.server
import ipaddress
import json
from pathlib import Path
import ssl
import shutil
import subprocess
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def authority(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--workdir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = args.workdir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    key, ca = authority('COS local regression CA')
    _, other_ca = authority('Untrusted regression CA')
    pem = ca.public_bytes(serialization.Encoding.PEM)
    other_pem = other_ca.public_bytes(serialization.Encoding.PEM)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    server_cert = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
                   .issuer_name(ca.subject).public_key(server_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                   .sign(key, hashes.SHA256()))
    (root / 'server.pem').write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    (root / 'server.key').write_bytes(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    paths = {}
    for name, folder, content in [
        ('ascii', 'ascii/ClassIn', pem),
        ('chinese', '粵語課資料/ClassIn', pem),
        ('bundle', '中文安装目录/ClassIn', other_pem + pem),
        ('untrusted', 'untrusted', other_pem),
        ('corrupt', 'corrupt', b'not a certificate'),
    ]:
        path = root / folder / 'cacert.pem'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        paths[name] = path
    paths['missing'] = root / 'missing.pem'
    upload = root / '备课资料' / '测试板书.edpx'
    upload.parent.mkdir(exist_ok=True)
    payload = b'cos-ca-utf8-upload-probe'
    upload.write_bytes(payload)
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_PUT(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            received.append(body)
            self.send_response(200)
            self.send_header('Content-Length', '3')
            self.send_header('ETag', '"' + hashlib.md5(body).hexdigest() + '"')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(b'ACK')

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    results = []
    try:
        for branch in (0, 1, 2):
            for name, ca_path in paths.items():
                before = len(received)
                executable = args.probe.resolve()
                if name in ('chinese', 'bundle'):
                    destination = ca_path.parent / executable.name
                    shutil.copy2(executable, destination)
                    for library in executable.parent.glob('*.dll'):
                        shutil.copy2(library, ca_path.parent / library.name)
                    executable = destination
                process = subprocess.run([str(executable), str(branch),
                                          f'https://127.0.0.1:{server.server_port}/upload',
                                          str(ca_path), str(upload)], capture_output=True, timeout=15)
                expect_success = name in ('ascii', 'chinese', 'bundle')
                delivered = received[before:]
                passed = (process.returncode == (0 if expect_success else 1) and
                          (delivered == [payload] if expect_success else not delivered))
                row = {'branch': branch, 'case': name, 'passed': passed,
                       'executable': str(executable),
                       'expected_success': expect_success, 'returncode': process.returncode,
                       'received': len(delivered), 'stdout': process.stdout.decode('utf-8', errors='replace'),
                       'stderr': process.stderr.decode('utf-8', errors='replace')}
                results.append(row)
                print(f"branch={branch} case={name} passed={passed} received={len(delivered)}", flush=True)
    finally:
        server.shutdown()
        server.server_close()
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    return 0 if all(row['passed'] for row in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())

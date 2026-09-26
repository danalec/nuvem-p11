"""TLS trust-store tests.

The security-relevant invariant: the peer chain must validate against the 12 CAs embedded
in the official module, and the *system* trust store is never consulted. A loopback server
with a self-signed certificate is the direct way to observe that.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading

import pytest

from nuvem_p11.errors import TransportError
from nuvem_p11.transport import exchange
from nuvem_p11.trust import CA_FILES, CA_DIR, build_context, ca_paths

import os

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl CLI required")

REQUEST = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    directory = tmp_path_factory.mktemp("tls")
    key = directory / "key.pem"
    cert = directory / "cert.pem"
    subprocess.run(
        [
            OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "2",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    return str(key), str(cert)


class LoopbackServer:
    def __init__(self, key: str, cert: str) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.context = context
        self.cert = cert
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(4)
        self.port = self.socket.getsockname()[1]
        self.handshake_failed = threading.Event()
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.socket.settimeout(0.2)
        while not self._stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            try:
                with self.context.wrap_socket(connection, server_side=True) as tls:
                    tls.settimeout(2)
                    try:
                        tls.recv(65536)
                    except OSError:
                        pass
                    tls.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                    )
            except ssl.SSLError:
                self.handshake_failed.set()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        self.socket.close()


@pytest.fixture
def server(certificate):
    key, cert = certificate
    instance = LoopbackServer(key, cert)
    try:
        yield instance
    finally:
        instance.close()


def test_all_twelve_bundled_cas_load():
    assert len(CA_FILES) == 12
    for name in CA_FILES:
        path = os.path.join(CA_DIR, name)
        assert os.path.exists(path), name
        with open(path) as handle:
            assert handle.read().startswith("-----BEGIN CERTIFICATE-----")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    for path in ca_paths():
        context.load_verify_locations(cafile=path)


def test_extra_ca_is_appended_to_the_store(tmp_path):
    assert len(ca_paths("/tmp/extra.pem")) == 13
    assert ca_paths("/tmp/extra.pem")[-1] == "/tmp/extra.pem"


def test_a_peer_that_does_not_chain_to_the_bundled_cas_is_rejected(server):
    """The store is the bundled CAs and nothing else: a self-signed peer is not trusted."""
    with pytest.raises(TransportError):
        exchange("localhost", server.port, REQUEST, timeout=5)
    assert server.handshake_failed.wait(2)


def test_the_same_peer_is_accepted_once_its_certificate_is_trusted(server):
    """Proves the rejection above comes from the trust store, not from a broken fixture."""
    response = exchange("localhost", server.port, REQUEST, extra_ca=server.cert, timeout=5)
    assert response.status == 200
    assert response.body == b"{}"


def test_the_hostname_is_verified_along_with_the_chain(server):
    """A chain is not an identity: any of those CAs would sign a certificate for any name.

    So a peer whose chain is trusted but whose certificate is not valid for the name being
    contacted must be refused. Connecting by address is the cheap way to see it: the cert
    only carries ``DNS:localhost``.
    """
    with pytest.raises(TransportError):
        exchange("127.0.0.1", server.port, REQUEST, extra_ca=server.cert, timeout=5)


def test_the_context_asks_for_both_checks():
    context = build_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED

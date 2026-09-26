"""Enrollment tests: machine registration, certificate listing, config persistence.

Two layers, mirroring the existing suites: the request bytes and the error mapping are
exercised with the recorded ``exchange`` of :mod:`tests.test_protocol`, and one test
drives ``register_machine`` over the loopback TLS server technique of
:mod:`tests.test_trust` so the real transport is on the path.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import threading

import pytest

from nuvem_p11 import client as client_module
from nuvem_p11 import config as config_module
from nuvem_p11.client import (
    APP_OS,
    APP_VERSION,
    CERTIFICATES_PATH,
    MACHINE_PATH,
    SerproIDClient,
)
from nuvem_p11.config import (
    AMBIENTE_DEV,
    AMBIENTE_HOMOLOG,
    AMBIENTE_PRODUCTION,
    AMBIENTE_TEST,
    Config,
    Log,
)
from nuvem_p11.errors import BackendError
from nuvem_p11.transport import Response

CRLF = "\r\n"
OPENSSL = shutil.which("openssl")

HOST = "serproid.serpro.gov.br"
MACHINE_ID = "3f2a91c4e0b74d8a5c1f6e2d9b0a7c4e18d5f3a2"


class FakeBackend:
    """Records requests and replays scripted responses."""

    def __init__(self, responses: list[Response]) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, str, bytes]] = []

    def __call__(self, host, port, request, **kwargs) -> Response:
        self.requests.append((host, port, request))
        if not self.responses:
            raise AssertionError("unexpected extra request")
        return self.responses.pop(0)


def raw_response(status: int, body: bytes = b"", reason: str = "X") -> Response:
    return Response(status=status, reason=reason, body=body)


def json_array(items: list[dict]) -> Response:
    return Response(status=200, reason="OK", body=json.dumps(items).encode())


def split_request(raw: bytes) -> tuple[str, str, dict[str, str]]:
    """``(method, path, headers)`` of one recorded raw request."""
    head, _, _ = raw.partition(b"\r\n\r\n")
    lines = head.decode("utf-8").split(CRLF)
    method, path, _ = lines[0].split(" ")
    headers = dict(line.split(": ", 1) for line in lines[1:])
    return method, path, headers


@pytest.fixture
def client(tmp_path, monkeypatch):
    def build(responses, **kwargs):
        backend = FakeBackend(responses)
        monkeypatch.setattr(client_module, "exchange", backend)
        kwargs.setdefault("log", False)
        kwargs.setdefault("notify", None)
        return SerproIDClient(home=str(tmp_path), **kwargs), backend

    return build


def config_dir(home: str) -> str:
    return os.path.join(home, ".config", "serproid")


def write_config(home: str, *, ambiente: str | None = None, machine_id: str | None = None) -> None:
    directory = config_dir(home)
    os.makedirs(directory, exist_ok=True)
    if ambiente is not None:
        with open(os.path.join(directory, "ambiente"), "w") as handle:
            handle.write(ambiente)
    if machine_id is not None:
        with open(os.path.join(directory, "maquinaId"), "w") as handle:
            handle.write(machine_id)


# --- registration -----------------------------------------------------------------------


def test_register_machine_request_is_byte_exact(client, tmp_path):
    write_config(str(tmp_path), ambiente="2", machine_id=MACHINE_ID)
    instance, backend = client([raw_response(200, json.dumps({"identificador": "abc"}).encode())])

    assert instance.register_machine() == "abc"

    host, port, raw = backend.requests[0]
    assert (host, port) == (HOST, "443")
    assert raw == CRLF.join(
        [
            f"POST {MACHINE_PATH} HTTP/1.1",
            f"Host: {HOST}",
            f"X-SMARTCERT-UUID: {MACHINE_ID}",
            f"x-app-version: {APP_VERSION}",
            f"x-app-so: {APP_OS}",
            "Connection: close",
            "Content-Length: 0",
            "",
            "",
        ]
    ).encode()


def test_register_machine_headers_seen_by_the_backend(client, tmp_path):
    write_config(str(tmp_path), ambiente="2", machine_id=MACHINE_ID)
    instance, backend = client([raw_response(200, json.dumps({"identificador": "abc"}).encode())])

    instance.register_machine()

    method, path, headers = split_request(backend.requests[0][2])
    assert (method, path) == ("POST", "/smartcert-api/api/drivers/maquina")
    assert headers["X-SMARTCERT-UUID"] == MACHINE_ID
    assert headers["x-app-so"] == "LINUX_64"
    assert headers["x-app-version"] == "2.1.6"
    assert headers["Connection"] == "close"
    assert headers["Content-Length"] == "0"


def test_uuid_header_is_omitted_without_a_machine_id(client, tmp_path):
    """The header is only sent when there is an id: an empty file means no header."""
    instance, backend = client([raw_response(200, b'{"identificador":"abc"}')])

    instance.register_machine()

    _, _, headers = split_request(backend.requests[0][2])
    assert "X-SMARTCERT-UUID" not in headers


def test_register_machine_persists_the_identifier(client, tmp_path):
    instance, _ = client([raw_response(200, json.dumps({"identificador": MACHINE_ID}).encode())])

    instance.register_machine()

    with open(os.path.join(config_dir(str(tmp_path)), "maquinaId")) as handle:
        assert handle.read() == MACHINE_ID
    # The persisted id is what the next request advertises.
    assert instance.endpoint().machine_id == MACHINE_ID


def test_register_machine_rejects_a_missing_identificador(client):
    instance, _ = client([raw_response(200, b"{}")])
    with pytest.raises(BackendError):
        instance.register_machine()


def test_register_machine_rejects_a_non_json_body(client):
    instance, _ = client([raw_response(200, b"<html>oops</html>")])
    with pytest.raises(BackendError):
        instance.register_machine()


@pytest.mark.parametrize("status", [400, 401, 404, 412, 500])
def test_register_machine_any_other_status_is_unhandled(client, status):
    instance, _ = client([raw_response(status, b"{}")])
    with pytest.raises(BackendError) as excinfo:
        instance.register_machine()
    assert str(excinfo.value) == "ERR-NAO-TRAT"


def test_register_machine_406_is_incompatible_version(client):
    instance, _ = client([raw_response(406)])
    with pytest.raises(BackendError) as excinfo:
        instance.register_machine()
    assert str(excinfo.value) == "VERSAO_APP_INCOMPATIVEL"


# --- certificate listing ----------------------------------------------------------------


def test_list_certificates_request_is_byte_exact(client, tmp_path):
    write_config(str(tmp_path), ambiente="2", machine_id=MACHINE_ID)
    instance, backend = client([json_array([])])

    assert instance.list_certificates() == []

    host, port, raw = backend.requests[0]
    assert (host, port) == (HOST, "443")
    assert raw == CRLF.join(
        [
            f"GET {CERTIFICATES_PATH} HTTP/1.1",
            f"Host: {HOST}",
            f"X-SMARTCERT-UUID: {MACHINE_ID}",
            f"x-app-version: {APP_VERSION}",
            f"x-app-so: {APP_OS}",
            "Connection: close",
            "",
            "",
        ]
    ).encode()


def test_list_certificates_returns_the_parsed_array(client, tmp_path):
    write_config(str(tmp_path), ambiente="2", machine_id=MACHINE_ID)
    payload = [
        {"id": 123456, "certificadoB64": "-----BEGIN CERTIFICATE-----\nAA\n", "certificadoP7b": "TUlJ"},
        {"id": 123457, "certificadoB64": "TUlJ", "certificadoP7b": None},
    ]
    instance, backend = client([json_array(payload)])

    assert instance.list_certificates() == payload

    method, path, headers = split_request(backend.requests[0][2])
    assert (method, path) == ("GET", "/smartcert-api/api/drivers/certificados")
    assert headers["X-SMARTCERT-UUID"] == MACHINE_ID
    assert "Content-Length" not in headers


@pytest.mark.parametrize("status", [401, 404, 412])
def test_list_certificates_unauthorized_statuses(client, status):
    instance, _ = client([raw_response(status)])
    with pytest.raises(BackendError) as excinfo:
        instance.list_certificates()
    assert str(excinfo.value) == "MAQ-NAO-AUT"


def test_list_certificates_406_is_incompatible_version(client):
    instance, _ = client([raw_response(406)])
    with pytest.raises(BackendError) as excinfo:
        instance.list_certificates()
    assert str(excinfo.value) == "VERSAO_APP_INCOMPATIVEL"


@pytest.mark.parametrize("status", [400, 500, 503])
def test_list_certificates_other_statuses_are_unhandled(client, status):
    instance, _ = client([raw_response(status)])
    with pytest.raises(BackendError) as excinfo:
        instance.list_certificates()
    assert str(excinfo.value) == "ERR-NAO-TRAT"


def test_list_certificates_rejects_a_non_array_body(client):
    instance, _ = client([raw_response(200, b'{"id": 1}')])
    with pytest.raises(BackendError):
        instance.list_certificates()


def test_list_certificates_rejects_an_invalid_body(client):
    instance, _ = client([raw_response(200, b"<html>oops</html>")])
    with pytest.raises(BackendError):
        instance.list_certificates()


# --- configuration persistence ----------------------------------------------------------


@pytest.mark.parametrize(
    "ambiente,expected",
    [(AMBIENTE_DEV, "0"), (AMBIENTE_HOMOLOG, "1"), (AMBIENTE_PRODUCTION, "2"), (AMBIENTE_TEST, "3")],
)
def test_write_ambiente_round_trip(tmp_path, ambiente, expected):
    config = Config(home=str(tmp_path), log=False)

    config.write_ambiente(ambiente)

    with open(os.path.join(config_dir(str(tmp_path)), "ambiente"), "rb") as handle:
        assert handle.read() == expected.encode()  # no trailing newline
    assert config.read_ambiente() == ambiente


@pytest.mark.parametrize(
    "ambiente,name",
    [
        (AMBIENTE_DEV, "maquinaIdDes"),
        (AMBIENTE_HOMOLOG, "maquinaIdHom"),
        (AMBIENTE_PRODUCTION, "maquinaId"),
        (AMBIENTE_TEST, "maquinaIdTes"),
    ],
)
def test_write_machine_id_round_trip(tmp_path, ambiente, name):
    config = Config(home=str(tmp_path), log=False)

    config.write_machine_id(ambiente, MACHINE_ID)

    with open(os.path.join(config_dir(str(tmp_path)), name), "rb") as handle:
        assert handle.read() == MACHINE_ID.encode()  # no trailing newline
    assert config.read_machine_id(ambiente) == MACHINE_ID


def test_write_machine_id_targets_only_the_current_environment(tmp_path):
    config = Config(home=str(tmp_path), log=False)

    config.write_machine_id(AMBIENTE_HOMOLOG, MACHINE_ID)

    assert config.read_machine_id(AMBIENTE_HOMOLOG) == MACHINE_ID
    assert config.read_machine_id(AMBIENTE_PRODUCTION) == ""
    assert config.read_machine_id(AMBIENTE_DEV) == ""


def test_writes_truncate_like_file_writer(tmp_path):
    config = Config(home=str(tmp_path), log=False)

    config.write_machine_id(AMBIENTE_PRODUCTION, MACHINE_ID)
    config.write_machine_id(AMBIENTE_PRODUCTION, "short")
    config.write_ambiente(AMBIENTE_PRODUCTION)
    config.write_ambiente(AMBIENTE_TEST)

    with open(os.path.join(config_dir(str(tmp_path)), "maquinaId")) as handle:
        assert handle.read() == "short"
    with open(os.path.join(config_dir(str(tmp_path)), "ambiente")) as handle:
        assert handle.read() == "3"


def test_write_failure_is_logged_and_swallowed(tmp_path):
    """``catch (IOException)`` + ``log.error``: a blocked config dir must not raise."""
    home = tmp_path / "home"
    (home / ".config").mkdir(parents=True)
    (home / ".config" / "serproid").write_text("not a directory")
    logger = Log(str(tmp_path), enabled=True)
    config = Config(home=str(home), log_override=logger)

    config.write_ambiente(AMBIENTE_HOMOLOG)
    config.write_machine_id(AMBIENTE_PRODUCTION, MACHINE_ID)

    log = open(logger.path).read()
    assert log.count("Erro ao tentar salvar informacao no diretorio de configuracoes") == 2


def test_round_trip_against_a_fresh_home(tmp_path):
    """A brand-new ``$HOME`` has no ``.config/serproid`` until something writes."""
    home = str(tmp_path / "fresh")
    os.makedirs(home)

    config = Config(home=home, log=False)
    config.write_ambiente(AMBIENTE_HOMOLOG)
    config.write_machine_id(AMBIENTE_HOMOLOG, MACHINE_ID)

    reopened = Config(home=home, log=False)
    assert reopened.read_ambiente() == AMBIENTE_HOMOLOG
    assert reopened.read_machine_id(AMBIENTE_HOMOLOG) == MACHINE_ID


# --- end to end over loopback TLS -------------------------------------------------------


@pytest.fixture(scope="module")
def tls_certificate(tmp_path_factory):
    if OPENSSL is None:
        pytest.skip("openssl CLI required")
    directory = tmp_path_factory.mktemp("enroll-tls")
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


class LoopbackBackend:
    """TLS server that records the raw request and replays one raw reply."""

    def __init__(self, key: str, cert: str, reply: bytes) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.context = context
        self.cert = cert
        self.reply = reply
        self.requests: list[bytes] = []
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(4)
        self.port = self.socket.getsockname()[1]
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
                    request = b""
                    while b"\r\n\r\n" not in request:
                        chunk = tls.recv(65536)
                        if not chunk:
                            break
                        request += chunk
                    self.requests.append(request)
                    tls.sendall(self.reply)
            except (ssl.SSLError, OSError):
                pass

    def close(self) -> None:
        self._stop.set()
        self.socket.close()
        self.thread.join(timeout=2)


def tls_client(tmp_path, monkeypatch, server: LoopbackBackend) -> SerproIDClient:
    monkeypatch.setattr(client_module, "DEFAULT_PORT", str(server.port))
    monkeypatch.setitem(config_module.HOSTS, AMBIENTE_PRODUCTION, "localhost")
    # O certificado do servidor de laço entra como CA confiável: a verificação (cadeia e
    # nome) continua ligada, em vez de desligada.
    return SerproIDClient(home=str(tmp_path), extra_ca=server.cert, log=False, notify=None)


def test_register_machine_over_real_tls(tmp_path, monkeypatch, tls_certificate):
    key, cert = tls_certificate
    body = json.dumps({"identificador": MACHINE_ID}).encode()
    reply = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )
    server = LoopbackBackend(key, cert, reply)
    try:
        instance = tls_client(tmp_path, monkeypatch, server)
        assert instance.register_machine() == MACHINE_ID
    finally:
        server.close()

    method, path, headers = split_request(server.requests[0])
    assert (method, path) == ("POST", "/smartcert-api/api/drivers/maquina")
    assert headers["x-app-version"] == "2.1.6"
    assert headers["x-app-so"] == "LINUX_64"
    assert Config(home=str(tmp_path), log=False).read_machine_id(AMBIENTE_PRODUCTION) == MACHINE_ID


def test_list_certificates_over_real_tls(tmp_path, monkeypatch, tls_certificate):
    key, cert = tls_certificate
    body = json.dumps([{"id": 7, "certificadoB64": "TUlJ", "certificadoP7b": None}]).encode()
    reply = (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )
    server = LoopbackBackend(key, cert, reply)
    try:
        instance = tls_client(tmp_path, monkeypatch, server)
        write_config(str(tmp_path), ambiente="2", machine_id=MACHINE_ID)
        assert instance.list_certificates() == [
            {"id": 7, "certificadoB64": "TUlJ", "certificadoP7b": None}
        ]
    finally:
        server.close()

    method, path, headers = split_request(server.requests[0])
    assert (method, path) == ("GET", "/smartcert-api/api/drivers/certificados")
    assert headers["X-SMARTCERT-UUID"] == MACHINE_ID

"""Protocol-level tests for the SerproID core.

The backend is replaced by a recorded ``exchange`` so the state machine, the exact request
bytes and the error mapping are all exercised deterministically. TLS itself is covered
separately by :mod:`tests.test_trust`.
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from nuvem_p11 import client as client_module
from nuvem_p11.client import (
    APP_OS,
    APP_VERSION,
    Endpoint,
    PssParams,
    SerproIDClient,
)
from nuvem_p11.config import (
    AMBIENTE_DEV,
    AMBIENTE_HOMOLOG,
    AMBIENTE_PRODUCTION,
    AMBIENTE_TEST,
    HOSTS,
    Config,
    c_strtol,
)
from nuvem_p11.errors import (
    CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED,
    AuthorizationCanceled,
    BackendError,
)
from nuvem_p11.transport import Response

CRLF = "\r\n"


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


def json_response(payload: dict, headers: list[tuple[str, str]] | None = None) -> Response:
    body = json.dumps(payload).encode()
    return Response(status=200, reason="OK", headers=headers or [], body=body)


@pytest.fixture
def client(tmp_path, monkeypatch):
    def build(responses, **kwargs):
        backend = FakeBackend(responses)
        monkeypatch.setattr(client_module, "exchange", backend)
        kwargs.setdefault("log", False)
        kwargs.setdefault("notify", None)
        return SerproIDClient(home=str(tmp_path), **kwargs), backend

    return build


def write_config(tmp_path: str, *, ambiente: str | None = None, machine_id: str | None = None) -> None:
    directory = os.path.join(tmp_path, ".config", "serproid")
    os.makedirs(directory, exist_ok=True)
    if ambiente is not None:
        with open(os.path.join(directory, "ambiente"), "w") as handle:
            handle.write(ambiente)
    if machine_id is not None:
        with open(os.path.join(directory, "maquinaId"), "w") as handle:
            handle.write(machine_id)


# --- request bytes ----------------------------------------------------------------------


def test_post_v1_request_is_byte_exact(client):
    instance, backend = client([json_response({"id": 42})])
    data = b"\x00\x01\x02\x03"
    endpoint = Endpoint(AMBIENTE_PRODUCTION, "serproid.serpro.gov.br", "443", "DEADBEEF")
    backend.responses = [json_response({"id": 42})]

    instance.submit(123456, data, endpoint=endpoint)

    _, _, raw = backend.requests[0]
    body = json.dumps(
        {
            "certificadoId": 123456,
            "desafio": base64.b64encode(data).decode(),
            "pid": str(instance.device.pid),
            "executavel": instance.device.basename,
        },
        separators=(",", ":"),
    )
    expected = CRLF.join(
        [
            "POST /smartcert-api/api/drivers/assinatura HTTP/1.1",
            "Host: serproid.serpro.gov.br",
            "Content-Type: application/json",
            "X-SMARTCERT-UUID: DEADBEEF",
            f"x-app-version: {APP_VERSION}",
            f"x-app-so: {APP_OS}",
            "Connection: close",
            f"Content-Length: {len(body.encode())}",
            "",
            "",
        ]
    ) + body + CRLF
    assert raw == expected.encode()


def test_post_v2_request_carries_hash_and_padding(client):
    instance, backend = client([])
    endpoint = Endpoint(AMBIENTE_PRODUCTION, "h", "443", "U")
    data = b"x" * 32
    body, version = instance._post_body(
        7, base64.b64encode(data).decode(), len(data), PssParams(0x250, 1, 32)
    )
    assert version == 2
    payload = json.loads(body)
    assert payload["algoritmoHash"] == "SHA2_256"
    assert payload["tipoPadding"] == "PSS_SALT_LEN_MD"
    assert payload["certificadoId"] == 7
    assert payload["pid"] == str(instance.device.pid)
    assert "v2" in instance._post_request(endpoint=endpoint, body=body, version=2).decode()


def test_padding_falls_back_when_salt_len_differs(client):
    instance, _ = client([])
    data = b"y" * 20
    body, _ = instance._post_body(1, base64.b64encode(data).decode(), len(data), PssParams(0x260, 1, 32))
    payload = json.loads(body)
    assert payload["algoritmoHash"] == "SHA2_384"
    assert payload["tipoPadding"] == "PSS"


def test_unknown_hash_algorithm_degrades_to_sha1(client):
    instance, _ = client([])
    body, _ = instance._post_body(1, "AA==", 1, PssParams(0x999, 1, 0))
    assert json.loads(body)["algoritmoHash"] == "SHA1"


def test_get_request_is_byte_exact(client):
    instance, backend = client([json_response({"status": "ACEITO", "desafioAssinado": "AA=="})])
    endpoint = Endpoint(AMBIENTE_PRODUCTION, "h", "443", "U")
    assert instance.poll_once(99887766, endpoint=endpoint) == ("ACEITO", "AA==")
    raw = backend.requests[0][2]
    assert raw == CRLF.join(
        [
            "GET /smartcert-api/api/drivers/assinatura/99887766 HTTP/1.1",
            "Host: h",
            "Content-Type: application/json",
            "Cache-Control: no-cache",
            "Connection: close",
            "X-SMARTCERT-UUID: U",
            "",
            "",
        ]
    ).encode()


# --- signature decoding -----------------------------------------------------------------


def test_accepted_status_returns_base64_decoded_signature(client):
    signature = bytes(range(256))
    instance, _ = client(
        [
            json_response({"id": 5, "notificacaoEnviada": True}),
            json_response({"status": "ACEITO", "desafioAssinado": base64.b64encode(signature).decode()}),
        ]
    )
    assert instance.sign(123456, b"payload") == signature


def test_refused_authorization_maps_to_canceled(client):
    instance, _ = client(
        [
            json_response({"id": 5, "notificacaoEnviada": True}),
            json_response({"status": "RECUSADO", "desafioAssinado": None}),
        ]
    )
    with pytest.raises(AuthorizationCanceled) as excinfo:
        instance.sign(1, b"payload")
    assert excinfo.value.ckr == CKR_FUNCTION_CANCELED


def test_twenty_waiting_replies_give_up(client, tmp_path):
    write_config(str(tmp_path), ambiente="2")
    responses = [json_response({"id": 9, "notificacaoEnviada": True})]
    responses += [
        json_response({"status": "AGUARDANDO", "desafioAssinado": None}) for _ in range(20)
    ]
    instance, backend = client(responses, poll_interval=0.0, log=True)
    with pytest.raises(AuthorizationCanceled) as excinfo:
        instance.sign(1, b"payload")
    assert excinfo.value.ckr == CKR_FUNCTION_CANCELED
    # 1 POST + exactly 20 polls
    assert len(backend.requests) == 21
    log = open(os.path.join(str(tmp_path), ".config", "serproid", "serproid.log")).read()
    assert "Retornando CKR_FUNCTION_CANCELED depois de receber 20 vezes AGUARDANDO." in log


def test_unknown_status_is_retried_without_consuming_an_attempt(client):
    instance, backend = client(
        [
            json_response({"id": 1, "notificacaoEnviada": True}),
            json_response({"status": "PENDENTE", "desafioAssinado": None}),
            json_response({"status": "ACEITO", "desafioAssinado": base64.b64encode(b"sig").decode()}),
        ],
        poll_interval=0.0,
    )
    assert instance.sign(1, b"p") == b"sig"
    assert len(backend.requests) == 3


# --- error mapping ----------------------------------------------------------------------


def test_missing_id_is_function_failed(client):
    instance, _ = client([json_response({"notificacaoEnviada": True})])
    with pytest.raises(BackendError) as excinfo:
        instance.sign(1, b"p")
    assert excinfo.value.ckr == CKR_FUNCTION_FAILED


def test_non_object_json_is_function_failed(client):
    instance, _ = client([Response(status=200, reason="OK", body=b'"a string"')])
    with pytest.raises(BackendError):
        instance.sign(1, b"p")


def test_poll_requires_both_status_keys(client):
    instance, _ = client([json_response({"status": "ACEITO"})])
    with pytest.raises(BackendError):
        instance.poll_once(1, endpoint=Endpoint(2, "h", "443", "U"))


def test_invalid_json_body_is_function_failed(client):
    instance, _ = client([Response(status=200, reason="OK", body=b"<html>oops</html>")])
    with pytest.raises(BackendError) as excinfo:
        instance.sign(1, b"p")
    assert excinfo.value.ckr == CKR_FUNCTION_FAILED


# --- side effects -----------------------------------------------------------------------


def test_update_header_writes_marker(client, tmp_path):
    write_config(str(tmp_path), ambiente="2")
    instance, _ = client(
        [json_response({"id": 3}, headers=[("x-app-update-available", "true")])]
    )
    instance.submit(1, b"p")
    marker = os.path.join(str(tmp_path), ".config", "serproid", "atualizar")
    assert open(marker).read() == "1"


def test_notification_fires_only_when_requested(client):
    calls = []
    instance, _ = client(
        [
            json_response({"id": 1, "notificacaoEnviada": True}),
            json_response({"status": "ACEITO", "desafioAssinado": "AA=="}),
        ]
    )
    instance.notify = lambda: calls.append(1) or 0
    instance.sign(1, b"p")
    assert calls == [1]

    calls.clear()
    instance2, _ = client(
        [
            json_response({"id": 1, "notificacaoEnviada": False}),
            json_response({"status": "ACEITO", "desafioAssinado": "AA=="}),
        ]
    )
    instance2.notify = lambda: calls.append(1) or 0
    instance2.sign(1, b"p")
    assert calls == []


# --- configuration ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [("2", 2), ("0", 0), ("3x", 3), ("", 0), ("abc", 0), ("  1 ", 1), ("-1", -1)],
)
def test_c_strtol_matches_libc(text, expected):
    assert c_strtol(text) == expected


def test_ambiente_resolution(tmp_path):
    directory = os.path.join(str(tmp_path), ".config", "serproid")
    os.makedirs(directory)
    with open(os.path.join(directory, "ambiente"), "w") as handle:
        handle.write("1")
    with open(os.path.join(directory, "maquinaIdHom"), "w") as handle:
        handle.write("ABC\n")
    config = Config(home=str(tmp_path), log=False)
    assert config.read_ambiente() == AMBIENTE_HOMOLOG
    assert config.host(AMBIENTE_HOMOLOG) == "hom.serproid.serpro.gov.br"
    assert config.read_machine_id(AMBIENTE_HOMOLOG) == "ABC"


def test_missing_ambiente_defaults_to_production(tmp_path):
    config = Config(home=str(tmp_path), log=False)
    assert config.read_ambiente() == AMBIENTE_PRODUCTION


def test_empty_ambiente_resolves_to_dev(tmp_path):
    """An empty file makes strtol return 0, i.e. the development host."""
    write_config(str(tmp_path), ambiente="")
    assert Config(home=str(tmp_path), log=False).read_ambiente() == AMBIENTE_DEV


def test_out_of_range_ambiente_warns_and_falls_back(tmp_path):
    write_config(str(tmp_path), ambiente="7")
    config = Config(home=str(tmp_path), log=True)
    assert config.read_ambiente() == AMBIENTE_PRODUCTION
    log = open(os.path.join(str(tmp_path), ".config", "serproid", "serproid.log")).read()
    assert "valor invalido para ambiente, usando valor 2 (producao)" in log


def test_host_table_matches_the_module():
    assert HOSTS[AMBIENTE_DEV] == "desneoid.np.estaleiro.serpro.gov.br"
    assert HOSTS[AMBIENTE_HOMOLOG] == "hom.serproid.serpro.gov.br"
    assert HOSTS[AMBIENTE_PRODUCTION] == "serproid.serpro.gov.br"
    assert HOSTS[AMBIENTE_TEST] == "tesneoid.np.estaleiro.serpro.gov.br"


def test_machine_id_file_per_environment(tmp_path):
    directory = os.path.join(str(tmp_path), ".config", "serproid")
    os.makedirs(directory)
    for name in ("maquinaId", "maquinaIdHom", "maquinaIdDes", "maquinaIdTes"):
        with open(os.path.join(directory, name), "w") as handle:
            handle.write(name)
    config = Config(home=str(tmp_path), log=False)
    assert config.read_machine_id(AMBIENTE_DEV) == "maquinaIdDes"
    assert config.read_machine_id(AMBIENTE_HOMOLOG) == "maquinaIdHom"
    assert config.read_machine_id(AMBIENTE_PRODUCTION) == "maquinaId"
    assert config.read_machine_id(AMBIENTE_TEST) == "maquinaIdTes"


def test_missing_machine_id_yields_empty_header(tmp_path):
    write_config(str(tmp_path), ambiente="2")
    assert Config(home=str(tmp_path), log=False).read_machine_id(AMBIENTE_PRODUCTION) == ""

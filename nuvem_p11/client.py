"""The cloud signing protocol.

End-to-end flow, as implemented by ``C_Sign`` in the official module:

1. resolve ``ambiente`` -> backend host, port and ``maquinaId*`` value;
2. ``POST /smartcert-api/api[/v2]/drivers/assinatura`` with the *base64* of the caller's data in
   ``desafio`` and the certificate id. Nothing is transformed on the way: for
   ``CKM_RSA_PKCS`` the caller supplies the DigestInfo -- hashing is its job, as the mechanism
   requires -- and the backend applies the PKCS#1 v1.5 padding and the private key over those
   bytes;
3. parse ``{"id": N, "notificacaoEnviada": bool}`` and, if requested, raise a desktop
   notification (this is the moment the phone receives its push);
4. poll ``GET /smartcert-api/api/drivers/assinatura/N`` every 2 s, up to 20 times, until
   ``status`` becomes ``ACEITO`` (``desafioAssinado`` holds the signature) or ``RECUSADO``;
5. return ``base64decode(desafioAssinado)`` verbatim.

Failures raise :class:`~nuvem_p11.errors.SerproIDError` subclasses carrying the exact
``CKR_*`` value the official module returns.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Mapping

from .config import DEFAULT_PORT, Config, DeviceInfo
from .errors import AuthorizationCanceled, BackendError, TransportError
from .transport import CRLF, Response, exchange

API_PREFIX = "/smartcert-api/api"
SIGN_PATH = f"{API_PREFIX}/drivers/assinatura"
SIGN_PATH_V2 = f"{API_PREFIX}/v2/drivers/assinatura"
MACHINE_PATH = f"{API_PREFIX}/drivers/maquina"
CERTIFICATES_PATH = f"{API_PREFIX}/drivers/certificados"

#: Textual codes ``Servicos`` raises as ``SmartCertException``, replicated verbatim.
ERROR_MACHINE_NOT_AUTHORIZED = "MAQ-NAO-AUT"
ERROR_APP_VERSION_INCOMPATIBLE = "VERSAO_APP_INCOMPATIVEL"
ERROR_UNHANDLED = "ERR-NAO-TRAT"

#: Map from ``CK_RSA_PKCS_PSS_PARAMS.hashAlg`` (a ``CKM_SHA*`` digest mechanism) to the
#: backend's ``algoritmoHash`` vocabulary. Anything else degrades to ``SHA1``.
ALGORITHM_NAMES: Mapping[int, str] = {
    0x210: "MD5",  # CKM_MD5
    0x250: "SHA2_256",  # CKM_SHA256
    0x255: "SHA2_224",  # CKM_SHA224
    0x260: "SHA2_384",  # CKM_SHA384
    0x270: "SHA2_512",  # CKM_SHA512
}
DEFAULT_ALGORITHM = "SHA1"

PSS = "PSS"
PSS_SALT_LEN_MD = "PSS_SALT_LEN_MD"

UPDATE_HEADER_LINE = "x-app-update-available: true"

#: The notification icon, shipped inside the package. The official desktop points at
#: ``/usr/share/serproid-desktop/SerproID.png``, which exists only where Serpro's package is
#: installed. This one is the same style -- rounded square, white monogram -- in a different
#: colour and with a different monogram, so the notification says which implementation is
#: asking for the PIN.
ICON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")

NOTIFY_ARGV = [
    "notify-send",
    "-i",
    ICON,
    "SerproID",
    "Foi enviado um pedido de PIN para o seu dispositivo.",
]

APP_VERSION = "2.1.6"
APP_OS = "LINUX_64"


@dataclass(frozen=True)
class PssParams:
    """``CK_RSA_PKCS_PSS_PARAMS``."""

    hash_alg: int
    mgf: int = 1
    salt_len: int = 0

    @property
    def algorithm(self) -> str:
        return ALGORITHM_NAMES.get(self.hash_alg, DEFAULT_ALGORITHM)


@dataclass(frozen=True)
class Endpoint:
    """Everything ``C_Sign`` resolves once, before it starts talking to the backend."""

    ambiente: int
    host: str
    port: str
    machine_id: str


def _notify_desktop() -> int:
    return subprocess.run(NOTIFY_ARGV, check=False).returncode


class SerproIDClient:
    """Signing client for the SerproID cloud token."""

    def __init__(
        self,
        *,
        home: str | None = None,
        ambiente: int | None = None,
        device: DeviceInfo | None = None,
        extra_ca: str | None = None,
        timeout: float = 30.0,
        poll_interval: float = 2.0,
        max_polls: int = 20,
        log: bool = True,
        notify: Callable[[], int] | None = _notify_desktop,
        config: Config | None = None,
    ) -> None:
        self.extra_ca = extra_ca
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        self.notify = notify
        self.config = config or Config(home=home, log=log)
        self.device = device or DeviceInfo.detect()
        self._ambiente = ambiente

    # --- resolution ----------------------------------------------------------------
    def endpoint(self) -> Endpoint:
        """Resolve host/port/``maquinaId`` for the configured ``ambiente``."""
        ambiente = self.config.read_ambiente() if self._ambiente is None else self._ambiente
        return Endpoint(
            ambiente=ambiente,
            host=self.config.host(ambiente),
            port=DEFAULT_PORT,
            machine_id=self.config.read_machine_id(ambiente),
        )

    # --- request building ----------------------------------------------------------
    def _post_request(
        self, *, endpoint: Endpoint, body: str, version: int
    ) -> bytes:
        path = SIGN_PATH_V2 if version == 2 else SIGN_PATH
        head = CRLF.join(
            [
                f"POST {path} HTTP/1.1",
                f"Host: {endpoint.host}",
                "Content-Type: application/json",
                f"X-SMARTCERT-UUID: {endpoint.machine_id}",
                f"x-app-version: {APP_VERSION}",
                f"x-app-so: {APP_OS}",
                "Connection: close",
                f"Content-Length: {len(body.encode('utf-8'))}",
                "",
                "",
            ]
        )
        # The original appends a trailing CRLF after the body.
        return (head + body + CRLF).encode("utf-8")

    @staticmethod
    def _get_request(*, endpoint: Endpoint, request_id: int) -> bytes:
        return CRLF.join(
            [
                f"GET {SIGN_PATH}/{request_id} HTTP/1.1",
                f"Host: {endpoint.host}",
                "Content-Type: application/json",
                "Cache-Control: no-cache",
                "Connection: close",
                f"X-SMARTCERT-UUID: {endpoint.machine_id}",
                "",
                "",
            ]
        ).encode("utf-8")

    @staticmethod
    def _app_headers(endpoint: Endpoint) -> list[str]:
        """The headers ``Servicos.conectar`` sets, in the same order.

        The official app only sends ``X-SMARTCERT-UUID`` when the id file is non-empty.
        """
        lines = [] if not endpoint.machine_id else [f"X-SMARTCERT-UUID: {endpoint.machine_id}"]
        lines.append(f"x-app-version: {APP_VERSION}")
        lines.append(f"x-app-so: {APP_OS}")
        return lines

    @classmethod
    def _machine_request(cls, *, endpoint: Endpoint) -> bytes:
        """``POST drivers/maquina``.

        ``novaMaquina`` uses ``HttpURLConnection`` without ``setDoOutput``, so the request
        genuinely has no body (no Content-Type either): ``Content-Length: 0``.
        """
        return CRLF.join(
            [
                f"POST {MACHINE_PATH} HTTP/1.1",
                f"Host: {endpoint.host}",
                *cls._app_headers(endpoint),
                "Connection: close",
                "Content-Length: 0",
                "",
                "",
            ]
        ).encode("utf-8")

    @classmethod
    def _certificates_request(cls, *, endpoint: Endpoint) -> bytes:
        """``GET drivers/certificados``, built by ``conectar`` plus ``GET``."""
        return CRLF.join(
            [
                f"GET {CERTIFICATES_PATH} HTTP/1.1",
                f"Host: {endpoint.host}",
                *cls._app_headers(endpoint),
                "Connection: close",
                "",
                "",
            ]
        ).encode("utf-8")

    def _post_body(
        self, certificate_id: int, desafio: str, data_len: int, pss: PssParams | None
    ) -> tuple[str, int]:
        # json.dumps keeps the original's compact layout (no spaces) and escapes anything
        # hostile in ``basename``; ensure_ascii=False keeps raw UTF-8 like the f-strings did.
        payload: dict = {
            "certificadoId": certificate_id,
            "desafio": desafio,
            "pid": str(self.device.pid),
            "executavel": self.device.basename,
        }
        if pss is None:
            return json.dumps(payload, separators=(",", ":"), ensure_ascii=False), 1
        # The original compares the PSS salt length against C_Sign's ulDataLen -- the
        # raw payload length, not the base64 length.
        padding = PSS_SALT_LEN_MD if pss.salt_len == data_len else PSS
        payload["algoritmoHash"] = pss.algorithm
        payload["tipoPadding"] = padding
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False), 2

    # --- transport -----------------------------------------------------------------
    def _send(self, endpoint: Endpoint, request: bytes) -> Response:
        return exchange(
            endpoint.host,
            endpoint.port,
            request,
            extra_ca=self.extra_ca,
            timeout=self.timeout,
            log=self.config.log,
        )

    # --- protocol steps ------------------------------------------------------------
    def submit(
        self,
        certificate_id: int,
        data: bytes,
        *,
        pss: PssParams | None = None,
        endpoint: Endpoint | None = None,
    ) -> int:
        """POST the signing request; return the backend-assigned request id."""
        endpoint = endpoint or self.endpoint()
        desafio = base64.b64encode(data).decode("ascii")
        body, version = self._post_body(certificate_id, desafio, len(data), pss)
        response = self._send(endpoint, self._post_request(endpoint=endpoint, body=body, version=version))

        if response.header_line("x-app-update-available") == UPDATE_HEADER_LINE:
            self.config.mark_update_available()

        payload = self._parse_json(response, "Erro no JSON recebido apos envio do desafio:")
        request_id = payload.get("id")
        if request_id is None:
            self.config.log(f"JSON recebido nao veio com id: {response.body!r}")
            raise BackendError("resposta sem id")
        if not isinstance(request_id, int) or isinstance(request_id, bool):
            raise BackendError(f"id nao inteiro: {request_id!r}")

        if payload.get("notificacaoEnviada", True) is True and self.notify is not None:
            try:
                code = self.notify()
            except OSError as exc:
                # A missing notify-send must not abandon a request the backend already holds:
                # the push is out, and the poll loop still has to run.
                self.config.log(f"Problema ao exibir mensagem: {exc}")
            else:
                if code < 0:
                    self.config.log(f"Problema ao exibir mensagem: {code}")
        return request_id

    def poll_once(
        self, request_id: int, *, endpoint: Endpoint | None = None
    ) -> tuple[str, str | None]:
        """One ``GET``; returns ``(status, desafioAssinado)``."""
        endpoint = endpoint or self.endpoint()
        response = self._send(endpoint, self._get_request(endpoint=endpoint, request_id=request_id))
        payload = self._parse_json(
            response, "Erro no JSON recebido na consulta do pedido de assinatura:"
        )
        if "status" not in payload or "desafioAssinado" not in payload:
            self.config.log(f"JSON nao veio com status ou desafioAssinado: {response.body!r}")
            raise BackendError("resposta sem status ou desafioAssinado")
        status = payload["status"]
        if not isinstance(status, str):
            raise BackendError(f"status nao textual: {status!r}")
        signed = payload.get("desafioAssinado")
        return status, signed if isinstance(signed, str) else None

    def sign(
        self,
        certificate_id: int,
        data: bytes,
        *,
        pss: PssParams | None = None,
        on_poll: Callable[[int, str], None] | None = None,
    ) -> bytes:
        """Ask the cloud token to sign ``data``; return the raw signature bytes.

        ``pss=None`` selects the v1 endpoint (``CKM_RSA_PKCS``); a :class:`PssParams`
        selects v2 (``CKM_RSA_PKCS_PSS``).
        """
        # Resolved once, like C_Sign: both the POST and every poll reuse it.
        endpoint = self.endpoint()

        try:
            request_id = self.submit(certificate_id, data, pss=pss, endpoint=endpoint)
        except (TransportError, BackendError) as exc:
            # The original collapses every POST-side failure to CKR_FUNCTION_FAILED.
            self.config.log("Erro ao enviar pedido de assinatura.")
            raise BackendError(str(exc)) from exc

        attempts = 1
        last = time.monotonic()
        while True:
            try:
                status, signed = self.poll_once(request_id, endpoint=endpoint)
            except TransportError as exc:
                self.config.log(f"Erro no JSON recebido na consulta do pedido de assinatura: {exc}")
                raise BackendError(str(exc)) from exc
            if on_poll is not None:
                on_poll(attempts, status)

            if status == "RECUSADO":
                raise AuthorizationCanceled("assinatura recusada no dispositivo")
            if status == "ACEITO":
                if signed is None:
                    raise BackendError("desafioAssinado ausente em ACEITO")
                try:
                    return base64.b64decode(signed)
                except (ValueError, TypeError) as exc:  # binascii.Error is a ValueError
                    self.config.log(f"desafioAssinado nao e base64: {signed!r}")
                    raise BackendError("desafioAssinado invalido") from exc
            if status == "AGUARDANDO":
                if attempts != self.max_polls:
                    remaining = self.poll_interval - (time.monotonic() - last)
                    if remaining > 0:
                        time.sleep(remaining)
                    last = time.monotonic()
                    attempts += 1
                    continue
                self.config.log(
                    "Retornando CKR_FUNCTION_CANCELED depois de receber "
                    f"{self.max_polls} vezes AGUARDANDO."
                )
                raise AuthorizationCanceled("tempo de espera esgotado")
            # Unknown status: retry immediately without consuming an attempt.
            last = time.monotonic()

    # --- enrollment ----------------------------------------------------------------
    def register_machine(self) -> str:
        """``POST drivers/maquina``; store and return the assigned ``identificador``.

        ``ControllerInicio`` writes the identifier to the current environment's file as
        soon as the service succeeds, so the next call already carries the UUID header.
        """
        endpoint = self.endpoint()
        response = self._send(endpoint, self._machine_request(endpoint=endpoint))
        if response.status == 406:
            raise BackendError(ERROR_APP_VERSION_INCOMPATIBLE)
        if response.status != 200:
            self.config.log(
                f"Erro ao cadastrar nova maquina: {response.status}\n{response.body!r}"
            )
            raise BackendError(ERROR_UNHANDLED)

        payload = self._parse_json(response, "Erro no JSON recebido apos cadastro de maquina:")
        identificador = payload.get("identificador")
        if not isinstance(identificador, str) or not identificador:
            self.config.log(f"JSON de cadastro nao veio com identificador: {response.body!r}")
            raise BackendError("resposta sem identificador")
        self.config.write_machine_id(endpoint.ambiente, identificador)
        return identificador

    def list_certificates(self) -> list[dict]:
        """``GET drivers/certificados``; the machine's certificates, still encoded.

        Each entry is the backend's raw object (``id``, ``certificadoB64``,
        ``certificadoP7b``); decoding belongs to the caller that installs them.
        """
        endpoint = self.endpoint()
        response = self._send(endpoint, self._certificates_request(endpoint=endpoint))
        # Order matters: the official client checks these three before the 406.
        if response.status in (401, 404, 412):
            raise BackendError(ERROR_MACHINE_NOT_AUTHORIZED)
        if response.status == 406:
            raise BackendError(ERROR_APP_VERSION_INCOMPATIBLE)
        if response.status != 200:
            self.config.log(f"Erro ao ler certificados - response code: {response.status}")
            raise BackendError(ERROR_UNHANDLED)
        return self._parse_array(response, "Erro no JSON recebido ao ler certificados:")

    # --- helpers --------------------------------------------------------------------
    def _parse_json(self, response: Response, error_message: str) -> dict:
        try:
            payload = json.loads(response.body.decode("utf-8", errors="replace") or "null")
        except json.JSONDecodeError as exc:
            self.config.log(f"{error_message} {response.body!r}")
            raise BackendError(f"{error_message} {exc}") from exc
        if not isinstance(payload, dict):
            self.config.log(f"JSON recebido nao veio como objeto: {response.body!r}")
            raise BackendError("resposta JSON nao e um objeto")
        return payload

    def _parse_array(self, response: Response, error_message: str) -> list[dict]:
        try:
            payload = json.loads(response.body.decode("utf-8", errors="replace") or "null")
        except json.JSONDecodeError as exc:
            self.config.log(f"{error_message} {response.body!r}")
            raise BackendError(f"{error_message} {exc}") from exc
        if not isinstance(payload, list):
            self.config.log(f"JSON recebido nao veio como array: {response.body!r}")
            raise BackendError("resposta JSON nao e um array")
        return payload

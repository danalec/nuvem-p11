"""Raw HTTP/1.1 over TLS, byte-for-byte like the original's BIO plumbing.

``sub_8d140``/``sub_8b710`` write hand-built request strings with ``BIO_puts`` and read the
reply with ``BIO_gets``; no HTTP client library is involved. Reproducing that keeps the
request bytes identical, including the unusual trailing CRLF after the body.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

from .errors import TransportError
from .trust import build_context

CRLF = "\r\n"
_HEADER_TERMINATOR = b"\r\n\r\n"


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def header_line(self, name: str) -> str | None:
        """Reconstruct ``Name: value`` as it appeared, for exact line comparisons."""
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return f"{key}: {value}"
        return None


def _recv_all(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        try:
            chunk = sock.recv(65536)
        except (TimeoutError, socket.timeout):
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _parse(raw: bytes) -> Response:
    head, _, rest = raw.partition(_HEADER_TERMINATOR)
    lines = head.split(b"\r\n") if head else []
    if not lines:
        raise TransportError("resposta vazia do backend")
    parts = lines[0].split(b" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError) as exc:
        raise TransportError(f"linha de status invalida: {lines[0]!r}") from exc
    reason = parts[2].decode("latin-1") if len(parts) > 2 else ""

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        headers.append((name.decode("latin-1"), value.strip().decode("latin-1")))

    # The original reads until the peer closes (Connection: close). Honour
    # Content-Length when present so a keep-alive peer cannot stall us.
    body = rest
    for name, value in headers:
        if name.lower() == "content-length":
            try:
                length = int(value)
            except ValueError:
                break
            if len(body) >= length:
                body = body[:length]
            break
    return Response(status=status, reason=reason, headers=headers, body=body)


def exchange(
    host: str,
    port: str | int,
    request: bytes,
    *,
    extra_ca=None,
    timeout: float = 30.0,
    log=None,
) -> Response:
    """Send one request over a fresh TLS connection and return the parsed reply."""
    context = build_context(extra_ca=extra_ca, log=log)
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            try:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    tls.settimeout(timeout)
                    tls.sendall(request)
                    data = _recv_all(tls)
            except ssl.SSLError as exc:
                raise TransportError(f"TLS: {exc}") from exc
    except OSError as exc:
        raise TransportError(f"conexao com {host}:{port}: {exc}") from exc

    if not data:
        if log is not None:
            log("SSL_get_peer_certificate veio NULL - sem certificado, ou sem conexao.")
        raise TransportError("sem resposta do backend")
    return _parse(data)

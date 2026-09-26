"""The trust store: the CA certificates this client accepts.

The store is built exclusively from the blobs in :data:`CA_FILES`; the *system* trust store is
never consulted, so a root installed locally cannot widen what this client accepts.

The peer must satisfy both halves of its identity: the certificate chain has to reach one of
these CAs **and** the certificate has to be valid for the hostname being contacted. Checking
only the chain would accept any certificate those CAs ever issued, for any name, which is not
the same guarantee at all.
"""

from __future__ import annotations

import os
import ssl

CA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca")

#: Filenames of the bundled roots and intermediates.
CA_FILES = (
    "icpbrasil-raiz-v2.pem",
    "ac-rfb-v3.pem",
    "serpro-raiz-homologacao.pem",
    "serpro-intermediaria-homv2.pem",
    "acserproacfv3-homologacao.pem",
    "isrg-root-x1.pem",
    "letsencrypt-r3.pem",
    "letsencrypt-r10.pem",
    "letsencrypt-r11.pem",
    "letsencrypt-r12.pem",
    "letsencrypt-r13.pem",
    "letsencrypt-r14.pem",
)


def ca_paths(extra: str | os.PathLike[str] | None = None) -> list[str]:
    """Bundled CA files, plus an optional caller-supplied bundle appended to the store."""
    paths = [os.path.join(CA_DIR, name) for name in CA_FILES]
    if extra:
        paths.append(os.fspath(extra))
    return paths


def build_context(
    *,
    extra_ca: str | os.PathLike[str] | None = None,
    cipher_list: str = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4",
    log=None,
) -> ssl.SSLContext:
    """TLS client context: chain **and** hostname verified, against the bundled CAs only.

    The hostname comes from ``wrap_socket(server_hostname=...)``, which is also what sets SNI,
    so the name that identifies the peer is the same one that gets verified.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    for path in ca_paths(extra_ca):
        context.load_verify_locations(cafile=path)

    try:
        context.set_ciphers(cipher_list)
    except ssl.SSLError as exc:  # pragma: no cover - OpenSSL version dependent
        # Failing an entire signature because a cipher string is unknown to the local OpenSSL
        # would be worse than logging it and letting the handshake negotiate.
        if log is not None:
            log(f"Erro SSL_set_cipher_list: {exc}")
    return context

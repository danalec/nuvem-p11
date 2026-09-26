"""Installing what the backend hands out.

``GET /drivers/certificados`` returns, per certificate, the user's own DER (base64 or PEM)
and the issuing chain as a PKCS#7 blob. The desktop installs all of it into the browsers'
NSS databases and drops the user's certificate in ``<config>/certificados/<id>.cer``, which
is where the PKCS#11 module reads it from.
"""

from __future__ import annotations

import base64
import os
import tempfile
from dataclasses import dataclass, field

from .config import Config
from .p11.der import DerError, certificates_from_pkcs7, subject_name, validity


def decode_blob(text: str) -> bytes:
    """Base64 out of a payload that may or may not carry PEM armour.

    The original strips the ``BEGIN``/``END`` lines and every ``\\n`` and then hands the
    rest to a decoder that skips anything outside the alphabet. ``str.split``-free for the
    same reason: we want the identical tolerance, not a stricter parser.
    """
    cleaned = (
        text.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----BEGIN PKCS7-----", "")
        .replace("\n", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("-----END PKCS7-----", "")
    )
    return base64.b64decode(cleaned, validate=False)


@dataclass(frozen=True)
class IssuedCertificate:
    """One entry of ``GET /drivers/certificados``, decoded."""

    certificate_id: int
    der: bytes
    chain: tuple[bytes, ...] = ()

    @property
    def label(self) -> str:
        try:
            return subject_name(self.der)
        except DerError:
            return str(self.certificate_id)

    def intermediates(self) -> tuple[bytes, ...]:
        """The chain without the leaf, oldest first.

        The original sorts the chain by ``notBefore`` and installs all but the last entry.
        That only happens to be right because the leaf is normally the newest certificate
        in the blob; here the leaf is identified by identity, and only an unmatched chain
        falls back to the original's rule.
        """
        chain = [cert for cert in self.chain if cert != self.der]
        if len(chain) == len(self.chain):
            chain = list(self.chain)[:-1] if self.chain else []
        try:
            chain.sort(key=lambda cert: validity(cert)[0])
        except DerError:
            pass
        return tuple(chain)


@dataclass
class InstallResult:
    """What the installation managed to do, mirroring ``ResultadoInstalacao``."""

    installed: list[str] = field(default_factory=list)
    certificates_dir: str = ""
    firefox: bool | None = None
    chrome: bool | None = None
    authorities: list[str] = field(default_factory=list)
    #: What the browser integration reported, including which profiles pointed elsewhere.
    details: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.firefox is not False and self.chrome is not False


def parse_certificates(payload: list[dict]) -> list[IssuedCertificate]:
    """Decode the backend's JSON array into DER."""
    issued: list[IssuedCertificate] = []
    for entry in payload:
        try:
            certificate_id = int(entry["id"])
            der = decode_blob(entry["certificadoB64"])
        except (KeyError, TypeError, ValueError):
            continue
        chain: tuple[bytes, ...] = ()
        raw_chain = entry.get("certificadoP7b")
        if raw_chain:
            try:
                chain = tuple(certificates_from_pkcs7(decode_blob(raw_chain)))
            except DerError:
                chain = ()
        issued.append(IssuedCertificate(certificate_id, der, chain))
    return issued


def install_user_certificates(
    config: Config, certificates: list[IssuedCertificate]
) -> list[str]:
    """Replace ``<config>/certificados`` with the given certificates, as the original does."""
    written: list[str] = []
    try:
        for name in os.listdir(config.certificates_dir):
            path = os.path.join(config.certificates_dir, name)
            if os.path.isfile(path):
                os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        config.log(f"Erro ao remover certificados anteriores: {error}")
        return written
    for certificate in certificates:
        path = config.certificate_path(certificate.certificate_id)
        try:
            os.makedirs(config.certificates_dir, exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(certificate.der)
            written.append(path)
        except OSError as error:
            config.log(f"Erro ao gravar {path}: {error}")
    return written


def _stage(der: bytes) -> str:
    """Write one certificate to a temporary file, like the original's ``createTempFile``."""
    handle = tempfile.NamedTemporaryFile(prefix="neoid", suffix="crt", delete=False)
    try:
        handle.write(der)
    finally:
        handle.close()
    return handle.name


def install(
    config: Config,
    certificates: list[IssuedCertificate],
    *,
    home: str,
    lib: str,
    runner=None,
) -> InstallResult:
    """Configure the browsers, then install the authorities and the certificates.

    ``browser`` is imported here rather than at module level so that decoding a backend
    payload does not require the NSS tools to be present. The caller resolves ``lib``: it
    must never be Serpro's module.
    """
    from . import browser

    runner = runner or browser.subprocess_runner
    result = InstallResult()
    config.log("Configurando SerproID")
    setup = browser.configure(home, lib=lib, runner=runner)
    result.firefox, result.chrome = setup.firefox, setup.chrome
    result.details = setup.details

    config.log("Instalando certificados de AC Raiz")
    result.authorities = browser.install_cas(home, runner=runner)

    config.log("Instalando certificados do usuário")
    written = install_user_certificates(config, certificates)
    result.certificates_dir = config.certificates_dir
    for certificate in certificates:
        for cert in certificate.intermediates():
            try:
                name = subject_name(cert)
            except DerError:
                continue
            path = _stage(cert)
            try:
                browser.install_ca_file(home, name, path, runner=runner)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        result.installed.append(certificate.label)
    config.log("Fim da instalação de certificados")
    if not written:
        result.installed = []
    return result

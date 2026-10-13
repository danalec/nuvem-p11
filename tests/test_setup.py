"""Installation: what the backend sends, and where it ends up.

The fixtures under ``tests/data`` are the public ICP-Brasil certificates that ship with the
official desktop, plus a PKCS#7 blob built from them with the ``openssl crl2pkcs7`` command
(in the same shape the backend returns in ``certificadoP7b``). No personal material is
stored here.
"""

from __future__ import annotations

import base64
import os

import pytest

from nuvem_p11.config import Config
from nuvem_p11.p11.der import (
    DerError,
    certificates_from_pkcs7,
    parse_certificate,
    subject_name,
    validity,
)
from nuvem_p11.setup import (
    IssuedCertificate,
    decode_blob,
    install_user_certificates,
    parse_certificates,
)

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

ROOT = "ICP-Brasilv5.der"
INTERMEDIATE = "acserprov4.der"
OTHER = "acserproacfv5.der"


def fixture(name: str) -> bytes:
    with open(os.path.join(DATA, name), "rb") as handle:
        return handle.read()


def pem(der: bytes) -> str:
    body = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----"


# --- decoding -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "build",
    [
        lambda der: base64.b64encode(der).decode(),
        pem,
        lambda der: pem(der).replace("\n", "\r\n") + "\r\n",
    ],
    ids=["bare base64", "pem", "pem with CRLF and a trailing newline"],
)
def test_decode_blob_accepts_every_shape_the_backend_sends(build):
    der = fixture(INTERMEDIATE)
    assert decode_blob(build(der)) == der


def test_decode_blob_survives_the_leading_newline_the_original_leaves():
    """The original strips ``-----BEGIN-----`` but not the ``\\n`` that follows it."""
    der = fixture(INTERMEDIATE)
    assert decode_blob("-----BEGIN CERTIFICATE-----\r\n" + base64.b64encode(der).decode()) == der


def test_parse_certificates_reads_a_realistic_payload():
    der = fixture(INTERMEDIATE)
    chain = fixture("chain.p7b")
    payload = [
        {
            "id": 123456,
            "certificadoB64": pem(der),
            "certificadoP7b": base64.b64encode(chain).decode(),
        }
    ]
    issued = parse_certificates(payload)
    assert len(issued) == 1
    assert issued[0].certificate_id == 123456
    assert issued[0].der == der
    assert len(issued[0].chain) == 3


def test_parse_certificates_skips_entries_it_cannot_use():
    payload = [
        {"id": "not a number", "certificadoB64": "AAAA"},
        {"certificadoB64": "AAAA"},
        {"id": 7, "certificadoB64": base64.b64encode(fixture(OTHER)).decode()},
    ]
    issued = parse_certificates(payload)
    assert [item.certificate_id for item in issued] == [7]


def test_parse_certificates_skips_a_null_certificate_field():
    """``certificadoB64: null`` is a skip, not an AttributeError that aborts the batch."""
    payload = [
        {"id": 1, "certificadoB64": None},
        {"id": 2, "certificadoB64": base64.b64encode(fixture(OTHER)).decode()},
    ]
    issued = parse_certificates(payload)
    assert [item.certificate_id for item in issued] == [2]


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag, len(content)]) + content


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def test_a_truncated_certificate_with_a_version_raises_der_error():
    """A short tbsCertificate with [0] version needs one more field; that is DerError, not IndexError."""
    tbs = _seq(
        _tlv(0xA0, b"\x02\x01\x02"),  # version [0] EXPLICIT
        _tlv(0x02, b"\x01"),  # serialNumber
        _seq(b""),  # signature
        _seq(b""),  # issuer
        _seq(b""),  # validity
        _seq(b""),  # subject -- subjectPublicKeyInfo is missing
    )
    with pytest.raises(DerError):
        parse_certificate(_seq(tbs))


def test_a_broken_chain_does_not_lose_the_certificate():
    payload = [
        {
            "id": 1,
            "certificadoB64": base64.b64encode(fixture(OTHER)).decode(),
            "certificadoP7b": base64.b64encode(b"not a pkcs7").decode(),
        }
    ]
    issued = parse_certificates(payload)
    assert issued[0].der == fixture(OTHER)
    assert issued[0].chain == ()


# --- chains -------------------------------------------------------------------------


def test_pkcs7_fixture_holds_exactly_the_bundled_certificates():
    """Regression on the fixture itself, so a bad regeneration cannot hide."""
    chain = certificates_from_pkcs7(fixture("chain.p7b"))
    assert chain == [fixture(ROOT), fixture(INTERMEDIATE), fixture(OTHER)]


def test_intermediates_drop_the_leaf_and_sort_by_not_before():
    leaf = fixture(OTHER)
    issued = IssuedCertificate(
        1, leaf, (fixture(INTERMEDIATE), leaf, fixture(ROOT))
    )
    intermediates = issued.intermediates()
    assert leaf not in intermediates
    assert list(intermediates) == sorted(intermediates, key=lambda cert: validity(cert)[0])
    assert set(intermediates) == {fixture(ROOT), fixture(INTERMEDIATE)}


def test_intermediates_fall_back_to_the_original_rule_without_the_leaf():
    """The official code sorts the chain and drops the last entry; keep that as a fallback."""
    issued = IssuedCertificate(1, b"", (fixture(ROOT), fixture(INTERMEDIATE)))
    intermediates = issued.intermediates()
    newest = max((fixture(ROOT), fixture(INTERMEDIATE)), key=lambda cert: validity(cert)[0])
    assert newest not in intermediates


def test_the_fallback_drops_the_newest_not_the_last_in_arrival_order():
    """Same rule, but with the chain delivered newest-first: sort first, then drop."""
    issued = IssuedCertificate(1, b"", (fixture(INTERMEDIATE), fixture(ROOT)))
    intermediates = issued.intermediates()
    newest = max((fixture(ROOT), fixture(INTERMEDIATE)), key=lambda cert: validity(cert)[0])
    assert newest not in intermediates
    assert set(intermediates) | {newest} == {fixture(ROOT), fixture(INTERMEDIATE)}


def test_the_label_is_the_subject_in_rfc2253_order():
    issued = IssuedCertificate(1, fixture(ROOT))
    assert issued.label == subject_name(fixture(ROOT))
    assert issued.label.startswith("CN=Autoridade Certificadora Raiz Brasileira v5,")
    assert issued.label.endswith(",C=BR")


# --- writing ------------------------------------------------------------------------


def test_install_user_certificates_replaces_the_directory(tmp_path):
    config = Config(home=str(tmp_path), log=False)
    os.makedirs(config.certificates_dir)
    stale = config.certificate_path(999999)
    with open(stale, "wb") as handle:
        handle.write(b"old")

    issued = [
        IssuedCertificate(123456, fixture(INTERMEDIATE)),
        IssuedCertificate(123457, fixture(OTHER)),
    ]
    written = install_user_certificates(config, issued)

    assert written == [config.certificate_path(123456), config.certificate_path(123457)]
    assert not os.path.exists(stale)
    assert open(config.certificate_path(123456), "rb").read() == fixture(INTERMEDIATE)
    assert sorted(os.listdir(config.certificates_dir)) == ["123456.cer", "123457.cer"]


def test_install_user_certificates_creates_the_directory_when_missing(tmp_path):
    config = Config(home=str(tmp_path), log=False)
    assert not os.path.isdir(config.certificates_dir)
    install_user_certificates(config, [IssuedCertificate(1, b"\x30\x00")])
    assert open(config.certificate_path(1), "rb").read() == b"\x30\x00"

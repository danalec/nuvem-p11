"""Minimal DER/ASN.1 reader and the X.509 fields the token has to expose.

The official module reads ``<id>.cer`` as DER and serves ``CKA_VALUE`` as the file bytes
verbatim, deriving ``CKA_SUBJECT``/``CKA_ISSUER``/``CKA_SERIAL_NUMBER`` and the modulus from
the structure. Reproducing that needs no crypto dependency, just a TLV walk.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Tag numbers we care about (context-specific bits stripped where noted).
SEQUENCE = 0x30
SET = 0x31
INTEGER = 0x02
BIT_STRING = 0x03
OID = 0x06
UTF8_STRING = 0x0C
PRINTABLE_STRING = 0x13
IA5_STRING = 0x16
BMP_STRING = 0x1E
TELEXT_STRING = 0x14

OID_COMMON_NAME = "2.5.4.3"


class DerError(ValueError):
    """The blob is not the DER we expect."""


def _length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise DerError("truncated length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 4:
        raise DerError(f"unsupported length form: {first:#x}")
    end = offset + 1 + count
    if end > len(data):
        raise DerError("truncated long length")
    return int.from_bytes(data[offset + 1 : end], "big"), end


def read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Return ``(tag, content, next_offset)``."""
    if offset >= len(data):
        raise DerError("truncated tag")
    tag = data[offset]
    length, content_start = _length(data, offset + 1)
    content_end = content_start + length
    if content_end > len(data):
        raise DerError("truncated content")
    return tag, data[content_start:content_end], content_end


def read_tlv_full(data: bytes, offset: int) -> tuple[int, bytes, bytes, int]:
    """Return ``(tag, full_tlv_bytes, content, next_offset)``."""
    tag, content, next_offset = read_tlv(data, offset)
    header = data[offset : next_offset - len(content)]
    return tag, header + content, content, next_offset


def children(data: bytes, offset: int = 0, end: int | None = None):
    """Iterate ``(tag, full, content, offset)`` over a constructed value's children."""
    end = len(data) if end is None else end
    while offset < end:
        tag, full, content, offset = read_tlv_full(data, offset)
        yield tag, full, content, offset


def decode_oid(content: bytes) -> str:
    if not content:
        raise DerError("empty OID")
    first = content[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(part) for part in parts)


def _decode_string(tag: int, content: bytes) -> str:
    if tag == BMP_STRING:
        return content.decode("utf-16-be", errors="replace")
    return content.decode("utf-8", errors="replace")


def common_names(name_der: bytes) -> list[str]:
    """Every ``CN`` in a DER ``Name``, in encounter order."""
    found: list[str] = []
    tag, _, content, _ = read_tlv_full(name_der, 0)
    if tag != SEQUENCE:
        raise DerError("Name is not a SEQUENCE")
    for _, _, rdn, _ in children(content):
        # RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        for _, _, attribute, _ in children(rdn):
            items = list(children(attribute))
            if len(items) < 2:
                continue
            if items[0][0] != OID or decode_oid(items[0][2]) != OID_COMMON_NAME:
                continue
            found.append(_decode_string(items[1][0], items[1][2]))
    return found


def _unsigned(content: bytes) -> bytes:
    """DER INTEGERs carry a leading 0x00 when the high bit is set; PKCS#11 wants the value."""
    stripped = content.lstrip(b"\x00")
    return stripped or b"\x00"


@dataclass(frozen=True)
class CertificateInfo:
    """The fields the token derives from one ``.cer`` file."""

    subject: bytes  # DER Name, verbatim
    issuer: bytes  # DER Name, verbatim
    serial: bytes  # INTEGER content bytes, verbatim (CKA_SERIAL_NUMBER)
    common_name: str
    modulus: bytes  # RSAPublicKey modulus, verbatim (CKA_MODULUS)
    public_exponent: bytes

    @property
    def serial_decimal(self) -> int:
        return int.from_bytes(self.serial, "big")

    @property
    def label(self) -> str:
        """The module labels objects as ``(<serial in decimal>) <CN>``."""
        return f"({self.serial_decimal}) {self.common_name}"


def parse_certificate(der: bytes) -> CertificateInfo:
    """Extract the fields the token exposes from a DER X.509 certificate."""
    tag, _, certificate, _ = read_tlv_full(der, 0)
    if tag != SEQUENCE:
        raise DerError("Certificate is not a SEQUENCE")

    outer = list(children(certificate))
    if not outer or outer[0][0] != SEQUENCE:
        raise DerError("Certificate has no tbsCertificate")
    tbs = list(children(outer[0][2]))
    if len(tbs) < 6:
        raise DerError("tbsCertificate too short")

    index = 0
    if tbs[0][0] == 0xA0:  # version [0] EXPLICIT
        index = 1
    if len(tbs) <= index + 5:
        raise DerError("tbsCertificate too short")

    serial_tag, _, serial, _ = tbs[index]
    if serial_tag != INTEGER:
        raise DerError("serialNumber is not an INTEGER")

    # signature AlgorithmIdentifier at index+1
    issuer_tag, issuer_full, _, _ = tbs[index + 2]
    if issuer_tag != SEQUENCE:
        raise DerError("issuer is not a SEQUENCE")

    # validity at index+3
    subject_tag, subject_full, _, _ = tbs[index + 4]
    if subject_tag != SEQUENCE:
        raise DerError("subject is not a SEQUENCE")

    spki_tag, _, spki, _ = tbs[index + 5]
    if spki_tag != SEQUENCE:
        raise DerError("subjectPublicKeyInfo is not a SEQUENCE")

    items = list(children(spki))
    if len(items) < 2 or items[1][0] != BIT_STRING:
        raise DerError("subjectPublicKeyInfo has no BIT STRING")
    key_bits = items[1][2]
    if not key_bits or key_bits[0] != 0:
        raise DerError("unexpected BIT STRING padding")

    rsa_tag, _, rsa, _ = read_tlv_full(key_bits, 1)
    if rsa_tag != SEQUENCE:
        raise DerError("public key is not an RSAPublicKey SEQUENCE")
    rsa_items = list(children(rsa))
    if len(rsa_items) < 2:
        raise DerError("RSAPublicKey incomplete")
    modulus = _unsigned(rsa_items[0][2])
    exponent = _unsigned(rsa_items[1][2])

    names = common_names(subject_full)
    return CertificateInfo(
        subject=subject_full,
        issuer=issuer_full,
        serial=serial,
        common_name=names[0] if names else "",
        modulus=modulus,
        public_exponent=exponent,
    )


# --- the extra fields the desktop installer needs ----------------------------------

#: RFC 4514 keywords; Java's ``X500Principal.getName()`` prints the same words and falls
#: back to the dotted OID for anything it does not know.
DN_OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "SERIALNUMBER",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "T",
    "2.5.4.42": "GIVENNAME",
    "1.2.840.113549.1.9.1": "EMAILADDRESS",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
}

_DN_SPECIAL = ',+"\\<>;'

UTCTIME = 0x17
GENERALIZED_TIME = 0x18


def _escape_dn_value(value: str) -> str:
    out = []
    last = len(value) - 1
    for index, char in enumerate(value):
        if char in _DN_SPECIAL:
            out.append("\\" + char)
        elif char == " " and (index == 0 or index == last):
            out.append("\\ ")
        else:
            out.append(char)
    return "".join(out)


def name_string(name_der: bytes, *, reverse: bool = True) -> str:
    """RFC 4514 string for a DER ``Name``.

    ``reverse`` matches both ``X500Principal.getName()`` and ``openssl x509 -subject``:
    the RDNs come out in the opposite order to the DER encoding (``CN=...,C=BR``).
    """
    tag, _, content, _ = read_tlv_full(name_der, 0)
    if tag != SEQUENCE:
        raise DerError("Name is not a SEQUENCE")
    relative: list[str] = []
    for _, _, rdn, _ in children(content):
        attributes: list[str] = []
        for _, _, attribute, _ in children(rdn):
            items = list(children(attribute))
            if len(items) < 2 or items[0][0] != OID:
                continue
            oid = decode_oid(items[0][2])
            attributes.append(
                f"{DN_OID_NAMES.get(oid, oid)}="
                f"{_escape_dn_value(_decode_string(items[1][0], items[1][2]))}"
            )
        relative.append("+".join(attributes))
    if reverse:
        relative.reverse()
    return ",".join(relative)


def _parse_time(tag: int, content: bytes) -> datetime:
    text = content.decode("ascii", errors="replace").strip()
    offset = timedelta(0)
    if text.endswith("Z"):
        text = text[:-1]
    elif len(text) >= 5 and text[-5] in "+-":
        sign = 1 if text[-5] == "+" else -1
        offset = sign * timedelta(hours=int(text[-4:-2]), minutes=int(text[-2:]))
        text = text[:-5]
    else:
        # Local time with no zone; the standard forbids it, but do not blow up on it.
        return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if tag == UTCTIME:
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        parsed = datetime.strptime(f"{year:04d}{text[2:]}", "%Y%m%d%H%M%S")
    elif tag == GENERALIZED_TIME:
        parsed = datetime.strptime(text, "%Y%m%d%H%M%S")
    else:
        raise DerError(f"not a Time: {tag:#x}")
    return parsed.replace(tzinfo=timezone.utc) - offset


def validity(der: bytes) -> tuple[datetime, datetime]:
    """``(notBefore, notAfter)`` of a DER certificate."""
    fields = _tbs(der)
    if len(fields) < 4:
        raise DerError("tbsCertificate too short")
    validity_tag, _, validity_content, _ = fields[3]
    if validity_tag != SEQUENCE:
        raise DerError("validity is not a SEQUENCE")
    times = list(children(validity_content))
    if len(times) < 2:
        raise DerError("validity has fewer than two times")
    return (
        _parse_time(times[0][0], times[0][2]),
        _parse_time(times[1][0], times[1][2]),
    )


def _tbs(der: bytes) -> list[tuple[int, bytes, bytes, int]]:
    """The ``tbsCertificate`` fields, with the optional ``[0] version`` already dropped.

    Index 0 is ``serialNumber``, 1 the signature algorithm, 2 the issuer, 3 validity,
    4 the subject and 5 the ``subjectPublicKeyInfo``.
    """
    tag, _, certificate, _ = read_tlv_full(der, 0)
    if tag != SEQUENCE:
        raise DerError("Certificate is not a SEQUENCE")
    outer = list(children(certificate))
    if not outer or outer[0][0] != SEQUENCE:
        raise DerError("Certificate has no tbsCertificate")
    fields = list(children(outer[0][2]))
    if fields and fields[0][0] == 0xA0:  # version [0] EXPLICIT
        fields = fields[1:]
    return fields


def subject_name(der: bytes) -> str:
    """RFC 4514 subject of a complete DER certificate."""
    fields = _tbs(der)
    if len(fields) < 5:
        raise DerError("tbsCertificate has no subject")
    return name_string(fields[4][1])


def issuer_name(der: bytes) -> str:
    """RFC 4514 issuer of a complete DER certificate."""
    fields = _tbs(der)
    if len(fields) < 3:
        raise DerError("tbsCertificate has no issuer")
    return name_string(fields[2][1])


def certificates_from_pkcs7(der: bytes) -> list[bytes]:
    """Every certificate of a PKCS#7 ``SignedData``, as complete DER TLVs.

    ``ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }`` and
    the certificates ride in ``SignedData``'s ``[0] IMPLICIT SET OF Certificate``, so the
    context tag's content is simply the concatenation of the certificate TLVs.
    """
    tag, _, outer, _ = read_tlv_full(der, 0)
    if tag != SEQUENCE:
        raise DerError("PKCS#7 is not a SEQUENCE")
    signed_data = None
    for item in children(outer):
        if item[0] == 0xA0:
            inner_tag, _, inner, _ = read_tlv_full(item[2], 0)
            if inner_tag != SEQUENCE:
                raise DerError("ContentInfo content is not a SEQUENCE")
            signed_data = inner
            break
    if signed_data is None:
        raise DerError("PKCS#7 has no content")
    for item in children(signed_data):
        if item[0] == 0xA0:
            return [full for t, full, _, _ in children(item[2]) if t == SEQUENCE]
    raise DerError("PKCS#7 SignedData carries no certificates")

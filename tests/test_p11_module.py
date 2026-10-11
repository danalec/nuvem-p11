"""Behavioural contract of the PKCS#11 layer, driven through the real C ABI.

The calls here go through a ctypes ``CK_FUNCTION_LIST`` built by :mod:`nuvem_p11.p11.cabi`,
so what is exercised is the same marshalling a loader would use. A synthetic certificate is
generated per session, keeping the suite independent of whatever is installed on the machine.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import ssl
import subprocess

import pytest

from nuvem_p11.config import Config
from nuvem_p11.errors import (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    CKR_SESSION_HANDLE_INVALID,
)
from nuvem_p11.p11 import constants as k
from nuvem_p11.p11.cabi import Binding, callables_at
from nuvem_p11.p11.module import (
    FAKE_KEY_HANDLE_2,
    FAKE_WRAPPING_KEY_HANDLE,
    MAX_SIGNATURE_PAYLOAD,
    Token,
)

OPENSSL = shutil.which("openssl")
CERT_ID = 123456

pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl CLI required")


class Attribute(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ulong),
        ("pValue", ctypes.c_void_p),
        ("ulValueLen", ctypes.c_ulong),
    ]


def attribute(type_: int, value: bytes | None) -> Attribute:
    if value is None:
        return Attribute(type_, None, 0)
    buffer = ctypes.create_string_buffer(value, len(value))
    return Attribute(type_, ctypes.cast(buffer, ctypes.c_void_p), len(value))


class StubClient:
    """Stands in for the cloud: records requests and returns a fixed signature."""

    def __init__(self, signature: bytes = bytes(range(256)), fail: Exception | None = None) -> None:
        self.signature = signature
        self.fail = fail
        self.calls: list[tuple[int, bytes, object]] = []

    def sign(self, certificate_id, data, *, pss=None, on_poll=None):
        if self.fail is not None:
            raise self.fail
        self.calls.append((certificate_id, data, pss))
        return self.signature


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    directory = tmp_path_factory.mktemp("p11")
    der = directory / "cert.der"
    subprocess.run(
        [
            OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/C=BR/O=ICP-Brasil/CN=TESTE DA SILVA:12345678909",
            "-outform", "DER", "-out", str(der), "-keyout", str(directory / "key.pem"),
        ],
        check=True,
        capture_output=True,
    )
    return der.read_bytes()


@pytest.fixture
def p11(tmp_path, certificate):
    home = tmp_path / "home"
    certificates = home / ".config" / "serproid" / "certificados"
    certificates.mkdir(parents=True)
    (certificates / f"{CERT_ID}.cer").write_bytes(certificate)

    def build(*, client=None) -> tuple[Token, dict]:
        config = Config(home=str(home), log=False)
        token = Token(config=config, client=client)
        binding = Binding(token)
        return token, callables_at(binding.address())

    return build


def open_session(f):
    assert f["C_Initialize"](None) == 0
    session = ctypes.c_ulong()
    assert f["C_OpenSession"](1, k.CKF_SERIAL_SESSION, None, None, ctypes.byref(session)) == 0
    assert session.value == k.SESSION_HANDLE
    return session.value


def find(f, session, class_id):
    template = attribute(k.CKA_CLASS, class_id.to_bytes(8, "little"))
    code = f["C_FindObjectsInit"](session, ctypes.byref(template), 1)
    if code:
        return code, []
    handles = (ctypes.c_ulong * 32)()
    count = ctypes.c_ulong()
    assert f["C_FindObjects"](session, handles, 32, ctypes.byref(count)) == 0
    f["C_FindObjectsFinal"](session)
    return 0, list(handles)[: count.value]


def get_attribute(f, session, handle, type_):
    """Returns ``(rc, length, bytes|None)``."""
    probe = attribute(type_, None)
    code = f["C_GetAttributeValue"](session, handle, ctypes.byref(probe), 1)
    if code != 0 or probe.ulValueLen in (0, 0xFFFFFFFFFFFFFFFF):
        return code, probe.ulValueLen, None
    buffer = ctypes.create_string_buffer(probe.ulValueLen)
    probe.pValue = ctypes.cast(buffer, ctypes.c_void_p)
    code = f["C_GetAttributeValue"](session, handle, ctypes.byref(probe), 1)
    return code, probe.ulValueLen, buffer.raw[: probe.ulValueLen]


# --- identity ----------------------------------------------------------------------


def test_library_and_slot_identity(p11):
    _, f = p11()
    assert f["C_Initialize"](None) == 0
    # A second initialisation is refused, like the original.
    assert f["C_Initialize"](None) == 0x191

    from tools.dump_module import Info, SlotInfo, TokenInfo

    info = Info()
    assert f["C_GetInfo"](ctypes.byref(info)) == 0
    assert (info.cryptokiVersion.major, info.cryptokiVersion.minor) == (2, 20)
    assert info.manufacturerID == b"SERPRO"
    assert info.libraryDescription == b"Modulo PKCS#11 SERPRO SerproID"
    assert (info.libraryVersion.major, info.libraryVersion.minor) == (3, 11)

    count = ctypes.c_ulong(0)
    assert f["C_GetSlotList"](0, None, ctypes.byref(count)) == 0
    assert count.value == 1
    slots = (ctypes.c_ulong * 1)()
    assert f["C_GetSlotList"](1, slots, ctypes.byref(count)) == 0
    assert list(slots) == [k.SLOT_ID]

    slot_info = SlotInfo()
    assert f["C_GetSlotInfo"](k.SLOT_ID, ctypes.byref(slot_info)) == 0
    assert slot_info.slotDescription == b"Slot SerproID"
    assert slot_info.flags == 0x7
    assert f["C_GetSlotInfo"](2, ctypes.byref(slot_info)) == 3


def test_token_info_is_reproduced_exactly(p11):
    _, f = p11()
    f["C_Initialize"](None)
    from tools.dump_module import TokenInfo

    token = TokenInfo()
    assert f["C_GetTokenInfo"](k.SLOT_ID, ctypes.byref(token)) == 0
    assert token.flags == 0x50A
    assert token.ulMinPinLen == 4
    assert token.ulMaxPinLen == 0x100
    assert token.ulMaxSessionCount == k.CK_UNAVAILABLE_INFORMATION
    assert token.ulTotalPublicMemory == 0xF000 and token.ulFreePublicMemory == 0

    raw = memoryview(token).cast("B")
    # The original NUL-pads these fixed-width fields (a spec deviation p11tool dislikes).
    assert bytes(raw[0:32]) == b"SerproID" + b"\x00" * 24
    assert bytes(raw[80:96]) == b"1" + b"\x00" * 15
    assert bytes(raw[64:80]) == b"SERPRO SerproID "


def test_mechanisms(p11):
    _, f = p11()
    f["C_Initialize"](None)
    count = ctypes.c_ulong(0)
    assert f["C_GetMechanismList"](k.SLOT_ID, None, ctypes.byref(count)) == 0
    assert count.value == 2
    mechanisms = (ctypes.c_ulong * 2)()
    f["C_GetMechanismList"](k.SLOT_ID, mechanisms, ctypes.byref(count))
    assert list(mechanisms) == [k.CKM_RSA_PKCS, k.CKM_RSA_PKCS_PSS]

    info = (ctypes.c_ulong * 3)()
    assert f["C_GetMechanismInfo"](k.SLOT_ID, k.CKM_RSA_PKCS, ctypes.byref(info)) == 0
    assert list(info) == [0x800, 0x800, 0x7B00]
    assert f["C_GetMechanismInfo"](k.SLOT_ID, 0x2233, ctypes.byref(info)) == CKR_MECHANISM_INVALID


# --- sessions ----------------------------------------------------------------------


def test_session_requires_serial_flag_and_login_accepts_any_pin(p11):
    _, f = p11()
    f["C_Initialize"](None)
    session = ctypes.c_ulong()
    assert f["C_OpenSession"](1, 0, None, None, ctypes.byref(session)) == CKR_SESSION_PARALLEL_NOT_SUPPORTED
    assert f["C_Login"](1, k.CKU_USER, None, 0) == CKR_SESSION_HANDLE_INVALID
    assert f["C_OpenSession"](1, k.CKF_SERIAL_SESSION, None, None, ctypes.byref(session)) == 0
    # No PIN is validated locally: the phone authorises the signature.
    assert f["C_Login"](session.value, k.CKU_USER, None, 0) == 0


# --- objects -----------------------------------------------------------------------


def test_object_handles_are_the_certificate_id(p11):
    _, f = p11()
    session = open_session(f)
    assert find(f, session, k.CKO_CERTIFICATE) == (0, [CERT_ID])
    assert find(f, session, k.CKO_PRIVATE_KEY) == (0, [CERT_ID | k.KEY_HANDLE_FLAG])
    assert find(f, session, k.CKO_PUBLIC_KEY) == (0, [])
    assert find(f, session, k.CKO_SECRET_KEY) == (0, [])
    # Unknown classes are accepted but match nothing.
    assert find(f, session, 9) == (0, [])


def find_with(f, session, items, max_count=32):
    """``C_FindObjectsInit``/``C_FindObjects`` with an arbitrary template."""
    attributes = (Attribute * len(items))()
    keepalive = []
    for index, (type_, value) in enumerate(items):
        buffer = ctypes.create_string_buffer(value, len(value))
        keepalive.append(buffer)
        attributes[index] = Attribute(type_, ctypes.cast(buffer, ctypes.c_void_p), len(value))
    code = f["C_FindObjectsInit"](session, ctypes.cast(attributes, ctypes.POINTER(Attribute)), len(items))
    if code:
        return code, []
    handles = (ctypes.c_ulong * max_count)()
    count = ctypes.c_ulong()
    f["C_FindObjects"](session, handles, max_count, ctypes.byref(count))
    f["C_FindObjectsFinal"](session)
    return code, list(handles)[: count.value]


def test_private_key_search_by_id_returns_the_key_handle(p11):
    """How NSS pairs a certificate with its key -- and the shape that broke TLS.

    NSS finds the certificate, then looks the private key up by ``CKA_ID``. Returning both
    handles there hands back the certificate handle, ``C_SignInit`` refuses it with
    ``CKR_KEY_TYPE_INCONSISTENT`` and the client-authentication handshake fails.
    """
    _, f = p11()
    session = open_session(f)
    identifier = CERT_ID.to_bytes(8, "little")

    code, handles = find_with(f, session, [(k.CKA_CLASS, (k.CKO_PRIVATE_KEY).to_bytes(8, "little")),
                                           (k.CKA_ID, identifier)])
    assert code == 0
    assert handles == [CERT_ID | k.KEY_HANDLE_FLAG]

    code, handles = find_with(f, session, [(k.CKA_CLASS, (k.CKO_CERTIFICATE).to_bytes(8, "little")),
                                           (k.CKA_ID, identifier)])
    assert code == 0 and handles == [CERT_ID]

    # Without a class, only the identifier comes back; an unknown id still yields a handle.
    code, handles = find_with(f, session, [(k.CKA_ID, identifier)])
    assert code == 0 and handles == [CERT_ID]
    code, handles = find_with(f, session, [(k.CKA_ID, (424242).to_bytes(8, "little"))])
    assert code == 0 and handles == [424242]


def test_an_id_filter_of_zero_stays_a_filter(p11):
    """``0`` is a real CKA_ID, not "no filter": it must not dump every handle."""
    _, f = p11()
    session = open_session(f)
    code, handles = find_with(f, session, [(k.CKA_ID, (0).to_bytes(8, "little"))])
    assert code == 0 and handles == [0]


def test_an_id_filter_of_the_wrong_size_is_refused(p11):
    """CKA_ID is a u64 here; reading a shorter buffer would touch caller memory past it."""
    _, f = p11()
    session = open_session(f)
    code, handles = find_with(f, session, [(k.CKA_ID, b"\x01\x02\x03\x04")])
    assert code == CKR_ATTRIBUTE_VALUE_INVALID and handles == []


def test_search_by_class_only(p11):
    _, f = p11()
    session = open_session(f)
    assert find_with(f, session, [(k.CKA_CLASS, (k.CKO_CERTIFICATE).to_bytes(8, "little"))])[1] == [CERT_ID]
    assert find_with(f, session, [(k.CKA_CLASS, (k.CKO_PRIVATE_KEY).to_bytes(8, "little"))])[1] == [
        CERT_ID | k.KEY_HANDLE_FLAG
    ]
    # Only private key, certificate and "no class" searches ever match.
    for class_id in (k.CKO_DATA, k.CKO_PUBLIC_KEY, k.CKO_SECRET_KEY, 9, 0xCE534354):
        assert find_with(f, session, [(k.CKA_CLASS, class_id.to_bytes(8, "little"))])[1] == []
    # No class at all reports both object kinds per certificate.
    assert find_with(f, session, [(k.CKA_TOKEN, b"\x01")])[1] == [CERT_ID, CERT_ID | k.KEY_HANDLE_FLAG]


def test_find_rejects_bad_templates(p11):
    _, f = p11()
    session = open_session(f)
    assert find_with(f, session, [(k.CKA_CLASS, (1).to_bytes(4, "little"))])[0] == CKR_ATTRIBUTE_VALUE_INVALID
    assert find_with(f, session, [(0x9999, b"\x00\x00\x00\x00")])[0] == CKR_ATTRIBUTE_TYPE_INVALID
    # A NULL attribute value is refused before anything else.
    template = Attribute(k.CKA_ID, None, 0)
    assert f["C_FindObjectsInit"](session, ctypes.byref(template), 1) == CKR_ATTRIBUTE_VALUE_INVALID


def test_closing_one_session_does_not_kill_the_token(p11):
    """NSS opens two sessions and closes one; the token must stay usable afterwards.

    ``C_CloseSession`` does not clear the session-open flag in the original -- only
    ``C_CloseAllSessions`` does. Clearing it here made every later call fail with
    ``CKR_SESSION_HANDLE_INVALID`` and NSS never enumerated the certificate.
    """
    _, f = p11()
    session = open_session(f)
    second = ctypes.c_ulong()
    assert f["C_OpenSession"](1, k.CKF_SERIAL_SESSION, None, None, ctypes.byref(second)) == 0
    assert find(f, session, k.CKO_CERTIFICATE) == (0, [CERT_ID])

    assert f["C_CloseSession"](session) == 0
    assert find(f, session, k.CKO_CERTIFICATE) == (0, [CERT_ID])
    # It does not even look at the handle.
    assert f["C_CloseSession"](999) == 0
    assert find(f, session, k.CKO_CERTIFICATE) == (0, [CERT_ID])

    assert f["C_CloseAllSessions"](k.SLOT_ID) == 0
    assert f["C_FindObjectsInit"](session, None, 0) == CKR_SESSION_HANDLE_INVALID


def test_login_state_machine(p11):
    """The original's own codes, including the odd ones."""
    _, f = p11()
    session = open_session(f)
    # A NULL output pointer is the only argument error the original checks for.
    assert f["C_GetSessionInfo"](session, None) == CKR_ARGUMENTS_BAD

    from tools.dump_module import SessionInfo

    info = SessionInfo()
    assert f["C_GetSessionInfo"](session, ctypes.byref(info)) == 0
    assert (info.slotID, info.state, info.flags) == (k.SLOT_ID, k.CKS_RO_PUBLIC_SESSION, 4)

    # Read-only session, CKU_SO: refused with CKR_SESSION_READ_ONLY_EXISTS.
    assert f["C_Login"](session, k.CKU_SO, None, 0) == 0xB7
    # CKU_CONTEXT_SPECIFIC is never valid.
    assert f["C_Login"](session, k.CKU_CONTEXT_SPECIFIC, None, 0) == 0x103
    # PIN is never inspected.
    assert f["C_Login"](session, k.CKU_USER, None, 0) == 0
    assert f["C_GetSessionInfo"](session, ctypes.byref(info)) == 0
    assert info.state == k.CKS_RO_USER_FUNCTIONS
    assert f["C_Login"](session, k.CKU_USER, None, 0) == 0x100
    assert f["C_Login"](session, k.CKU_SO, None, 0) == 0x104
    # Logout never changes the state.
    assert f["C_Logout"](session) == 0
    assert f["C_GetSessionInfo"](session, ctypes.byref(info)) == 0
    assert info.state == k.CKS_RO_USER_FUNCTIONS


def test_certificate_attributes(p11, certificate):
    _, f = p11()
    session = open_session(f)

    code, length, value = get_attribute(f, session, CERT_ID, k.CKA_VALUE)
    assert (code, length) == (0, len(certificate))
    assert value == certificate

    code, _, identifier = get_attribute(f, session, CERT_ID, k.CKA_ID)
    assert code == 0 and identifier == CERT_ID.to_bytes(8, "little")

    code, _, label = get_attribute(f, session, CERT_ID, k.CKA_LABEL)
    assert code == 0
    assert label.startswith(b"(") and label.endswith(b") TESTE DA SILVA:12345678909")
    # The prefix is the certificate serial in decimal.
    serial = int(label[1 : label.index(b")")])
    _, _, serial_der = get_attribute(f, session, CERT_ID, k.CKA_SERIAL_NUMBER)
    assert serial == int.from_bytes(serial_der, "big")

    code, length, modulus = get_attribute(f, session, CERT_ID, k.CKA_MODULUS)
    assert (code, length) == (0, 256)
    assert modulus[0] & 0x80  # a 2048-bit modulus has its top bit set

    # Unsupported attributes keep the original's CKR_ATTRIBUTE_TYPE_INVALID.
    assert get_attribute(f, session, CERT_ID, k.CKA_TRUSTED)[0] == CKR_ATTRIBUTE_TYPE_INVALID
    assert get_attribute(f, session, 999999, k.CKA_CLASS)[0] == CKR_OBJECT_HANDLE_INVALID


def test_private_key_object_hides_its_value(p11):
    _, f = p11()
    session = open_session(f)
    handle = CERT_ID | k.KEY_HANDLE_FLAG
    assert get_attribute(f, session, handle, k.CKA_VALUE) == (0, 0, None)
    code, _, modulus = get_attribute(f, session, handle, k.CKA_MODULUS)
    assert code == 0 and len(modulus) == 256
    code, _, private = get_attribute(f, session, handle, k.CKA_PRIVATE)
    assert code == 0 and private == b"\x01"


# --- signing -----------------------------------------------------------------------


def test_sign_init_rejects_bad_mechanisms_and_key_handles(p11):
    # A key handle without bit 31 set is refused.
    _, f = p11()
    session = open_session(f)
    mechanism = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0, 0)
    assert f["C_SignInit"](session, ctypes.byref(mechanism), CERT_ID) == CKR_KEY_TYPE_INCONSISTENT

    # An unadvertised mechanism is refused (and logged).
    _, f = p11()
    session = open_session(f)
    unknown = (ctypes.c_ulong * 3)(0xDEADBEEF, 0, 0)
    assert (
        f["C_SignInit"](session, ctypes.byref(unknown), CERT_ID | k.KEY_HANDLE_FLAG)
        == CKR_MECHANISM_INVALID
    )

    # CKM_RSA_PKCS takes no parameters.
    _, f = p11()
    session = open_session(f)
    with_parameters = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0x1000, 24)
    assert (
        f["C_SignInit"](session, ctypes.byref(with_parameters), CERT_ID | k.KEY_HANDLE_FLAG)
        == CKR_MECHANISM_PARAM_INVALID
    )

    # The valid combination.
    _, f = p11()
    session = open_session(f)
    assert f["C_SignInit"](session, ctypes.byref(mechanism), CERT_ID | k.KEY_HANDLE_FLAG) == 0
    # A second C_SignInit while a signing operation is armed is refused.
    assert (
        f["C_SignInit"](session, ctypes.byref(mechanism), CERT_ID | k.KEY_HANDLE_FLAG)
        == CKR_OPERATION_NOT_INITIALIZED
    )


def test_sign_requires_sign_init_and_reports_256_bytes(p11):
    _, f = p11()
    session = open_session(f)
    signature = ctypes.create_string_buffer(256)
    length = ctypes.c_ulong(256)
    payload = b"\x01" * 32

    assert f["C_Sign"](session, payload, len(payload), signature, ctypes.byref(length)) == CKR_OPERATION_NOT_INITIALIZED

    mechanism = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0, 0)
    assert f["C_SignInit"](session, ctypes.byref(mechanism), CERT_ID | k.KEY_HANDLE_FLAG) == 0
    # A NULL signature pointer is a size query: no network, and the operation stays active.
    query = ctypes.c_ulong(0)
    assert f["C_Sign"](session, payload, len(payload), None, ctypes.byref(query)) == 0
    assert query.value == k.SIGNATURE_LENGTH


def test_sign_returns_the_client_signature(p11):
    client = StubClient()
    _, f = p11(client=client)
    session = open_session(f)
    mechanism = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0, 0)
    assert f["C_SignInit"](session, ctypes.byref(mechanism), CERT_ID | k.KEY_HANDLE_FLAG) == 0

    payload = b"\xaa" * 32
    signature = ctypes.create_string_buffer(512)
    length = ctypes.c_ulong(512)
    assert f["C_Sign"](session, payload, len(payload), signature, ctypes.byref(length)) == 0
    assert length.value == k.SIGNATURE_LENGTH
    assert signature.raw[:256] == client.signature
    # pss=None selects the v1 request; the payload is forwarded verbatim.
    assert client.calls == [(CERT_ID, payload, None)]


def test_before_initialize_everything_is_refused(p11):
    _, f = p11()
    length = ctypes.c_ulong(0)
    assert f["C_Sign"](1, b"x", 1, None, ctypes.byref(length)) == CKR_CRYPTOKI_NOT_INITIALIZED
    assert f["C_GetSlotList"](0, None, ctypes.byref(length)) == CKR_CRYPTOKI_NOT_INITIALIZED


# --- capabilities the token does not have --------------------------------------------


def test_random_data_comes_from_the_os(p11):
    """A caller asking for randomness has no way to tell a constant from a key."""
    _, f = p11()
    session = open_session(f)
    first = ctypes.create_string_buffer(32)
    second = ctypes.create_string_buffer(32)
    assert f["C_GenerateRandom"](session, first, 32) == CKR_OK
    assert f["C_GenerateRandom"](session, second, 32) == CKR_OK
    assert first.raw[:32] != b"\x01" * 32
    assert first.raw[:32] != second.raw[:32]


def test_an_oversized_payload_is_refused_before_the_network(p11):
    client = StubClient()
    _, f = p11(client=client)
    session = open_session(f)
    mechanism = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0, 0)
    assert f["C_SignInit"](session, ctypes.byref(mechanism), CERT_ID | k.KEY_HANDLE_FLAG) == CKR_OK
    payload = b"x" * (MAX_SIGNATURE_PAYLOAD + 44)
    signature = ctypes.create_string_buffer(256)
    length = ctypes.c_ulong(256)
    code = f["C_Sign"](session, payload, len(payload), signature, ctypes.byref(length))
    assert code == CKR_ARGUMENTS_BAD
    assert client.calls == []


def test_a_short_signature_buffer_is_not_written_past(p11):
    """The caller declares how much room it has; writing anyway corrupts its memory."""
    client = StubClient(signature=b"s" * 256)
    _, f = p11(client=client)
    session = open_session(f)
    mechanism = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0, 0)
    assert f["C_SignInit"](session, ctypes.byref(mechanism), CERT_ID | k.KEY_HANDLE_FLAG) == CKR_OK
    signature = ctypes.create_string_buffer(8)
    length = ctypes.c_ulong(8)
    code = f["C_Sign"](session, b"d" * 32, 32, signature, ctypes.byref(length))
    assert code == CKR_BUFFER_TOO_SMALL
    assert signature.raw == b"\x00" * 8, "wrote past the buffer the caller declared"
    assert length.value == 256, "the size actually needed has to come back"


def test_digest_is_refused_rather_than_answered_with_a_constant(p11):
    """A constant digest makes integrity checks that always pass."""
    _, f = p11()
    session = open_session(f)
    mechanism = (ctypes.c_ulong * 3)(k.CKM_SHA_1, 0, 0)
    assert f["C_DigestInit"](session, ctypes.byref(mechanism)) == CKR_OK
    out = ctypes.create_string_buffer(20)
    length = ctypes.c_ulong(20)
    assert f["C_Digest"](session, b"data", 4, out, ctypes.byref(length)) == CKR_FUNCTION_NOT_SUPPORTED


def test_encrypt_and_decrypt_are_refused(p11):
    """Answering ``CKR_OK`` with a reversible transform the caller did not ask for is worse
    than refusing: nothing tells the caller the data was never encrypted."""
    _, f = p11()
    session = open_session(f)
    mechanism = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0, 0)
    payload = ctypes.create_string_buffer(16)
    out = ctypes.create_string_buffer(256)
    out_len = ctypes.c_ulong(256)
    for init, operation in (("C_EncryptInit", "C_Encrypt"), ("C_DecryptInit", "C_Decrypt")):
        assert f[init](session, ctypes.byref(mechanism), CERT_ID | k.KEY_HANDLE_FLAG) == CKR_OK
        code = f[operation](session, payload, 16, out, ctypes.byref(out_len))
        assert code == CKR_FUNCTION_NOT_SUPPORTED, operation


def test_verify_is_refused_rather_than_accepting_a_constant(p11):
    """Comparing against a fixed value reports a forged signature as valid."""
    _, f = p11()
    session = open_session(f)
    mechanism = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0, 0)
    assert f["C_VerifyInit"](session, ctypes.byref(mechanism), CERT_ID | k.KEY_HANDLE_FLAG) == CKR_OK
    assert f["C_Verify"](session, b"data", 4, b"\x00" * 256, 256) == CKR_FUNCTION_NOT_SUPPORTED


def test_wrapping_a_key_is_refused(p11):
    _, f = p11()
    session = open_session(f)
    mechanism = (ctypes.c_ulong * 3)(k.CKM_RSA_PKCS, 0, 0)
    assert f["C_WrapKey"](
        session, ctypes.byref(mechanism), FAKE_WRAPPING_KEY_HANDLE, FAKE_KEY_HANDLE_2, None, None
    ) == CKR_ARGUMENTS_BAD
    out = ctypes.create_string_buffer(256)
    out_len = ctypes.c_ulong(256)
    assert f["C_WrapKey"](
        session, ctypes.byref(mechanism), FAKE_WRAPPING_KEY_HANDLE, FAKE_KEY_HANDLE_2,
        out, ctypes.byref(out_len),
    ) == CKR_FUNCTION_NOT_SUPPORTED

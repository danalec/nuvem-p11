"""PKCS#11 entry points.

Every method here has the signature of the corresponding ``CK_*`` function and reads/writes
the caller's memory through ctypes, exactly like a C implementation would. Keeping the
signatures in Python (see :mod:`nuvem_p11.p11.cabi`) means the whole surface is testable
without a compiler, a browser or the shim.

What the token does:

* ``C_Sign`` is the only operation that leaves the machine: it asks the backend, which asks the
  phone. Everything else is local bookkeeping;
* one hard-coded slot (id 1) and one session handle (always 1);
* objects are synthesized from ``certificados/*.cer``: a certificate's handle is the numeric
  file name and its private key's handle is that value with bit 31 set;
* an operation the token cannot perform returns ``CKR_FUNCTION_NOT_SUPPORTED``. Answering
  ``CKR_OK`` with a transformation that is not the one the caller asked for is worse than
  refusing: the caller has no way to notice.
"""

from __future__ import annotations

import ctypes
import os

from ..client import PssParams, SerproIDClient
from ..config import Config, c_strtol
from ..errors import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_PARALLEL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    CKR_SIGNATURE_INVALID,
    CKR_SLOT_ID_INVALID,
    CKR_USER_NOT_LOGGED_IN,
    SerproIDError,
)
from . import constants as k
from .der import DerError, parse_certificate
from .trace import enabled as trace_enabled, trace

#: Largest payload accepted in one signing request. A request carries a digest-sized payload;
#: anything larger is refused before it reaches the network.
MAX_SIGNATURE_PAYLOAD = 756

OPERATION_STATE_BLOCK = b"\x01" * 16
FAKE_KEY_HANDLE = 1
FAKE_KEY_HANDLE_2 = 2
FAKE_WRAPPING_KEY_HANDLE = 3
FAKE_UNWRAPPING_KEY_HANDLE = 4

# Operation slots.
OP_NONE = 0
OP_FIND = 1
OP_ENCRYPT = 2
OP_DECRYPT = 3
OP_DIGEST = 4
OP_SIGN = 5
OP_SIGN_RECOVER = 6
OP_VERIFY = 7
OP_VERIFY_RECOVER = 8
OP_DIGEST_ENCRYPT = 9
OP_DIGEST_DECRYPT = 0xA
OP_SIGN_ENCRYPT = 0xB
OP_DECRYPT_VERIFY = 0xC

#: ``C_FindObjectsInit`` encodes the requested class as a small internal code, not as the
#: ``CKO_`` value: 1 data, 2 secret key, 3 public key, 4 private key, 5 certificate, and
#: :data:`FIND_NO_FILTER` when the template carries no class.
FIND_CLASS_CODES = {
    k.CKO_DATA: 1,
    k.CKO_SECRET_KEY: 2,
    k.CKO_PUBLIC_KEY: 3,
    k.CKO_PRIVATE_KEY: 4,
    k.CKO_CERTIFICATE: 5,
}
FIND_NO_FILTER = 100
FIND_DATA = 1
FIND_SECRET_KEY = 2
FIND_PUBLIC_KEY = 3
FIND_PRIVATE_KEY = 4
FIND_CERTIFICATE = 5

#: Attribute types ``C_FindObjectsInit`` understands; anything else is refused.
FIND_TEMPLATE_TYPES = {
    k.CKA_CLASS,
    k.CKA_TOKEN,
    k.CKA_CERTIFICATE_TYPE,
    k.CKA_ID,
    k.CKA_ISSUER,
    k.CKA_SUBJECT,
    k.CKA_VALUE,
}

#: Attribute types a certificate object answers.
CERTIFICATE_ATTRIBUTES = {
    k.CKA_CLASS,
    k.CKA_TOKEN,
    k.CKA_PRIVATE,
    k.CKA_LABEL,
    k.CKA_VALUE,
    k.CKA_CERTIFICATE_TYPE,
    k.CKA_ISSUER,
    k.CKA_SERIAL_NUMBER,
    k.CKA_KEY_TYPE,
    k.CKA_SUBJECT,
    k.CKA_ID,
    k.CKA_SENSITIVE,
}

#: Attribute types a private key object answers.
PRIVATE_KEY_ATTRIBUTES = {
    k.CKA_CLASS,
    k.CKA_TOKEN,
    k.CKA_PRIVATE,
    k.CKA_LABEL,
    k.CKA_VALUE,
    k.CKA_CERTIFICATE_TYPE,
    k.CKA_ISSUER,
    k.CKA_SERIAL_NUMBER,
    k.CKA_KEY_TYPE,
    k.CKA_SUBJECT,
    k.CKA_ID,
    k.CKA_SENSITIVE,
    k.CKA_MODULUS,
}


def _read(pointer, length: int) -> bytes:
    if not pointer or length <= 0:
        return b""
    return ctypes.string_at(pointer, length)


def _write(pointer, data: bytes) -> None:
    ctypes.memmove(pointer, data, len(data))


def _read_ulong(pointer) -> int:
    return ctypes.c_ulong.from_address(pointer).value


def _write_ulong(pointer, value: int) -> None:
    ctypes.c_ulong.from_address(pointer).value = value & 0xFFFFFFFFFFFFFFFF


def _write_byte(pointer, value: int) -> None:
    ctypes.c_ubyte.from_address(pointer).value = value & 0xFF


class Certificate:
    """One ``<id>.cer`` file, resolved lazily into PKCS#11 attributes."""

    def __init__(self, certificate_id: int, raw: bytes) -> None:
        self.certificate_id = certificate_id
        self.raw = raw
        self._info = None

    @property
    def info(self):
        if self._info is None:
            self._info = parse_certificate(self.raw)
        return self._info

    @property
    def key_handle(self) -> int:
        return self.certificate_id | k.KEY_HANDLE_FLAG


class Token:
    """The PKCS#11 state machine."""

    def __init__(
        self,
        *,
        home: str | None = None,
        extra_ca: str | None = None,
        config: Config | None = None,
        client: SerproIDClient | None = None,
    ) -> None:
        self.config = config or Config(home=home)
        self._extra_ca = extra_ca
        self._client = client

        self.initialized = False
        self.session_open = False
        self.session_state = k.CKS_RO_PUBLIC_SESSION

        self.operation = OP_NONE
        self.mechanism = None
        self.pss: PssParams | None = None
        self.certificate_id: int | None = None

        self._find_code = FIND_NO_FILTER
        self._find_id: int | None = None
        self._find_issuer: bytes | None = None
        self._find_subject: bytes | None = None
        self._find_value: bytes | None = None
        self._find_exhausted = False

    # --- helpers --------------------------------------------------------------------
    def client(self) -> SerproIDClient:
        if self._client is None:
            self._client = SerproIDClient(
                config=self.config,
                extra_ca=self._extra_ca,
                max_polls=self._poll_budget(),
            )
        return self._client

    @staticmethod
    def _poll_budget() -> int:
        """How many 2 s polls to allow while the user approves on the phone.

        Defaults to 20 polls of 2 s, about 40 s. ``NUVEM_P11_MAX_POLLS`` raises it: the push
        notification can take longer than that to reach the phone and come back.
        """
        raw = os.environ.get("NUVEM_P11_MAX_POLLS")
        if not raw:
            return 20
        try:
            value = int(raw)
        except ValueError:
            return 20
        return value if value > 0 else 20

    def _not_initialized(self) -> int:
        return CKR_OK if self.initialized else CKR_CRYPTOKI_NOT_INITIALIZED

    def _session_guard(self, hSession: int) -> int:
        """``CKR_SESSION_HANDLE_INVALID`` unless the one session (handle 1) is open."""
        if not self.session_open or hSession != k.SESSION_HANDLE:
            return CKR_SESSION_HANDLE_INVALID
        return CKR_OK

    def _slot_guard(self, slotID: int) -> int:
        return CKR_OK if slotID == k.SLOT_ID else CKR_SLOT_ID_INVALID

    def _reset_operation(self) -> None:
        self.operation = OP_NONE
        self.mechanism = None
        self.pss = None

    def certificates(self) -> list[Certificate]:
        """Every ``*.cer`` in ``certificados/``; the numeric prefix is the certificate id."""
        found: list[Certificate] = []
        try:
            entries = sorted(os.listdir(self.config.certificates_dir))
        except OSError:
            return found
        for name in entries:
            if ".cer" not in name:
                continue
            path = os.path.join(self.config.certificates_dir, name)
            try:
                with open(path, "rb") as handle:
                    raw = handle.read()
            except OSError:
                continue
            found.append(Certificate(c_strtol(name, 10), raw))
        return found

    # --- general-purpose ------------------------------------------------------------
    def C_Initialize(self, pInitArgs) -> int:
        if self.initialized:
            return CKR_CRYPTOKI_ALREADY_INITIALIZED
        self.initialized = True
        return CKR_OK

    def C_Finalize(self, pReserved) -> int:
        code = self._not_initialized()
        if code:
            return code
        # The token holds nothing that outlives the process; only the flag goes back.
        self.initialized = False
        return CKR_OK

    def C_GetInfo(self, pInfo) -> int:
        code = self._not_initialized()
        if code:
            return code
        if not pInfo:
            return CKR_ARGUMENTS_BAD

        class Version(ctypes.Structure):
            _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]

        class Info(ctypes.Structure):
            _fields_ = [
                ("cryptokiVersion", Version),
                ("manufacturerID", ctypes.c_char * 32),
                ("flags", ctypes.c_ulong),
                ("libraryDescription", ctypes.c_char * 32),
                ("libraryVersion", Version),
            ]

        info = Info.from_address(pInfo)
        info.cryptokiVersion.major, info.cryptokiVersion.minor = k.CRYPTOKI_VERSION
        info.manufacturerID = k.MANUFACTURER_ID.ljust(32, b"\x00")
        info.flags = 0
        info.libraryDescription = k.LIBRARY_DESCRIPTION.ljust(32, b"\x00")
        info.libraryVersion.major, info.libraryVersion.minor = k.LIBRARY_VERSION
        return CKR_OK

    def C_GetSlotList(self, tokenPresent, pSlotList, pulCount) -> int:
        code = self._not_initialized()
        if code:
            return code
        if not pulCount:
            return CKR_ARGUMENTS_BAD
        if pSlotList:
            if _read_ulong(pulCount) < 1:
                return CKR_BUFFER_TOO_SMALL
            _write_ulong(pSlotList, k.SLOT_ID)
        _write_ulong(pulCount, 1)
        return CKR_OK

    def C_GetSlotInfo(self, slotID, pInfo) -> int:
        code = self._not_initialized() or self._slot_guard(slotID)
        if code:
            return code
        if not pInfo:
            return CKR_ARGUMENTS_BAD

        class Version(ctypes.Structure):
            _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]

        class SlotInfo(ctypes.Structure):
            _fields_ = [
                ("slotDescription", ctypes.c_char * 64),
                ("manufacturerID", ctypes.c_char * 32),
                ("flags", ctypes.c_ulong),
                ("hardwareVersion", Version),
                ("firmwareVersion", Version),
            ]

        info = SlotInfo.from_address(pInfo)
        info.slotDescription = k.SLOT_DESCRIPTION.ljust(64, b"\x00")
        info.manufacturerID = k.MANUFACTURER_ID.ljust(32, b"\x00")
        info.flags = k.SLOT_FLAGS
        info.hardwareVersion.major, info.hardwareVersion.minor = k.SLOT_HARDWARE_VERSION
        info.firmwareVersion.major, info.firmwareVersion.minor = k.SLOT_FIRMWARE_VERSION
        return CKR_OK

    def C_GetTokenInfo(self, slotID, pInfo) -> int:
        code = self._not_initialized() or self._slot_guard(slotID)
        if code:
            return code
        if not pInfo:
            return CKR_ARGUMENTS_BAD

        class Version(ctypes.Structure):
            _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]

        class TokenInfo(ctypes.Structure):
            _fields_ = [
                ("label", ctypes.c_char * 32),
                ("manufacturerID", ctypes.c_char * 32),
                ("model", ctypes.c_char * 16),
                ("serialNumber", ctypes.c_char * 16),
                ("flags", ctypes.c_ulong),
                ("ulMaxSessionCount", ctypes.c_ulong),
                ("ulSessionCount", ctypes.c_ulong),
                ("ulMaxRwSessionCount", ctypes.c_ulong),
                ("ulRwSessionCount", ctypes.c_ulong),
                ("ulMaxPinLen", ctypes.c_ulong),
                ("ulMinPinLen", ctypes.c_ulong),
                ("ulTotalPublicMemory", ctypes.c_ulong),
                ("ulFreePublicMemory", ctypes.c_ulong),
                ("ulTotalPrivateMemory", ctypes.c_ulong),
                ("ulFreePrivateMemory", ctypes.c_ulong),
                ("hardwareVersion", Version),
                ("firmwareVersion", Version),
                ("utcTime", ctypes.c_char * 16),
            ]

        info = TokenInfo.from_address(pInfo)
        info.label = k.TOKEN_LABEL.ljust(32, b"\x00")
        info.manufacturerID = k.MANUFACTURER_ID.ljust(32, b"\x00")
        info.model = k.TOKEN_MODEL.ljust(16, b"\x00")[:16]
        info.serialNumber = k.TOKEN_SERIAL.ljust(16, b"\x00")
        info.flags = k.TOKEN_FLAGS
        open_sessions = 1 if self.session_open else 0
        info.ulMaxSessionCount = k.CK_UNAVAILABLE_INFORMATION
        info.ulSessionCount = open_sessions
        info.ulMaxRwSessionCount = k.CK_UNAVAILABLE_INFORMATION
        info.ulRwSessionCount = open_sessions
        info.ulMaxPinLen = k.TOKEN_MAX_PIN_LEN
        info.ulMinPinLen = k.TOKEN_MIN_PIN_LEN
        info.ulTotalPublicMemory = k.TOKEN_TOTAL_PUBLIC_MEMORY
        info.ulFreePublicMemory = k.TOKEN_FREE_PUBLIC_MEMORY
        info.ulTotalPrivateMemory = k.TOKEN_TOTAL_PRIVATE_MEMORY
        info.ulFreePrivateMemory = k.TOKEN_FREE_PRIVATE_MEMORY
        info.hardwareVersion.major, info.hardwareVersion.minor = k.TOKEN_HARDWARE_VERSION
        info.firmwareVersion.major, info.firmwareVersion.minor = k.TOKEN_FIRMWARE_VERSION
        info.utcTime = b"\x00" * 16
        return CKR_OK

    def C_GetMechanismList(self, slotID, pMechanismList, pulCount) -> int:
        code = self._not_initialized() or self._slot_guard(slotID)
        if code:
            return code
        if not pulCount:
            return CKR_ARGUMENTS_BAD
        mechanisms = k.ADVERTISED_MECHANISMS
        if pMechanismList:
            if _read_ulong(pulCount) < len(mechanisms):
                return CKR_BUFFER_TOO_SMALL
            for index, mechanism in enumerate(mechanisms):
                _write_ulong(pMechanismList + index * 8, mechanism)
        _write_ulong(pulCount, len(mechanisms))
        return CKR_OK

    def C_GetMechanismInfo(self, slotID, type, pInfo) -> int:
        code = self._not_initialized() or self._slot_guard(slotID)
        if code:
            return code
        if not pInfo:
            return CKR_ARGUMENTS_BAD
        entry = k.MECHANISM_INFO.get(type)
        if entry is None:
            return CKR_MECHANISM_INVALID
        minimum, maximum, flags = entry
        _write_ulong(pInfo, minimum)
        _write_ulong(pInfo + 8, maximum)
        _write_ulong(pInfo + 16, flags)
        return CKR_OK

    def C_InitToken(self, slotID, pPin, ulPinLen, pLabel) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._slot_guard(slotID)
        if code:
            return code
        if not pLabel:
            return CKR_ARGUMENTS_BAD
        if self.session_open:
            return 0xB6  # CKR_SESSION_EXISTS
        return CKR_OK

    def C_InitPIN(self, hSession, pPin, ulPinLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        # No SO session can be open, so logging out is always an error.
        return 0x101  # CKR_USER_NOT_LOGGED_IN

    def C_SetPIN(self, hSession, pOldPin, ulOldLen, pNewPin, ulNewLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if self.session_state in (k.CKS_RO_PUBLIC_SESSION, k.CKS_RO_USER_FUNCTIONS):
            return 0xB5  # CKR_SESSION_READ_ONLY
        if not pOldPin or not pNewPin:
            return CKR_ARGUMENTS_BAD
        return 0xA2  # CKR_PIN_INCORRECT -- the PIN is never validated here

    # --- sessions -------------------------------------------------------------------
    def C_OpenSession(self, slotID, flags, pApplication, Notify, phSession) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._slot_guard(slotID)
        if code:
            return code
        if not flags & k.CKF_SERIAL_SESSION:
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED
        if not phSession:
            return CKR_ARGUMENTS_BAD
        self.session_open = True
        # Only the CKF_RW_SESSION bit is kept: 0 = RO_PUBLIC, 2 = RW_PUBLIC.
        self.session_state = flags & k.CKF_RW_SESSION
        _write_ulong(phSession, k.SESSION_HANDLE)
        return CKR_OK

    def C_CloseSession(self, hSession) -> int:
        """Faithful: no session-handle argument is honoured, and the open flag survives.

        Only the operation and the session *state* are reset here; the open flag is cleared by
        ``C_CloseAllSessions`` alone. That matters in practice: NSS opens two sessions and
        closes one, so clearing the flag here makes every later call fail with
        ``CKR_SESSION_HANDLE_INVALID`` and the token is never enumerated.
        """
        if not self.initialized:
            return CKR_CRYPTOKI_NOT_INITIALIZED
        self._reset_operation()
        self.session_state = k.CKS_RO_PUBLIC_SESSION
        return CKR_OK

    def C_CloseAllSessions(self, slotID) -> int:
        code = self._not_initialized() or self._slot_guard(slotID)
        if code:
            return code
        self.session_open = False
        self.session_state = k.CKS_RO_PUBLIC_SESSION
        self._reset_operation()
        return CKR_OK

    def C_GetSessionInfo(self, hSession, pInfo) -> int:
        code = self._not_initialized()
        if code:
            return code
        if not pInfo:
            return CKR_ARGUMENTS_BAD
        code = self._session_guard(hSession)
        if code:
            return code
        # slotID, then the state and the flags derived from it.
        _write_ulong(pInfo, k.SLOT_ID)
        _write_ulong(pInfo + 8, self.session_state)
        _write_ulong(pInfo + 16, 4 if self.session_state < 2 else 6)
        return CKR_OK

    def C_GetOperationState(self, hSession, pOperationState, pulOperationStateLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if not pulOperationStateLen:
            return CKR_ARGUMENTS_BAD
        code = self._session_guard(hSession)
        if code:
            return code
        state = OPERATION_STATE_BLOCK * 16  # 256 bytes of 0x01
        if pOperationState:
            if _read_ulong(pulOperationStateLen) < len(state):
                return CKR_BUFFER_TOO_SMALL
            _write(pOperationState, state)
        _write_ulong(pulOperationStateLen, len(state))
        return CKR_OK

    def C_SetOperationState(self, hSession, pOperationState, ulLen, hEncKey, hAuthKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if ulLen != 0x100 or not pOperationState:
            return CKR_ARGUMENTS_BAD
        return CKR_OK

    def C_Login(self, hSession, userType, pPin, ulPinLen) -> int:
        """Faithful state machine, including its odd return codes.

        The PIN is never looked at -- authorisation happens on the phone. The codes: logging in
        as ``CKU_SO`` from a read-only session yields
        ``CKR_SESSION_READ_ONLY_EXISTS``, and an already-logged-in session reports
        ``CKR_USER_ALREADY_LOGGED_IN`` / ``CKR_USER_ANOTHER_ALREADY_LOGGED_IN``.
        """
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if userType >= k.CKU_CONTEXT_SPECIFIC:
            return 0x103  # CKR_USER_TYPE_INVALID

        if self.session_state == k.CKS_RO_PUBLIC_SESSION:
            if userType == k.CKU_SO:
                return 0xB7  # CKR_SESSION_READ_ONLY_EXISTS
            self.session_state = k.CKS_RO_USER_FUNCTIONS
            return CKR_OK
        if self.session_state == k.CKS_RW_PUBLIC_SESSION:
            self.session_state = (
                k.CKS_RW_SO_FUNCTIONS if userType == k.CKU_SO else k.CKS_RW_USER_FUNCTIONS
            )
            return CKR_OK
        return 0x104 if userType == k.CKU_SO else 0x100

    def C_Logout(self, hSession) -> int:
        """Faithful: never changes the session state."""
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        return 0x101 if (self.session_state & ~k.CKS_RW_PUBLIC_SESSION) == 0 else CKR_OK

    # --- objects --------------------------------------------------------------------
    def C_CreateObject(self, hSession, pTemplate, ulCount, phObject) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if not phObject:
            return CKR_ARGUMENTS_BAD
        if pTemplate and ulCount:
            for index in range(ulCount):
                base = pTemplate + index * 24
                if not _read_ulong(base + 8) or not _read_ulong(base + 16):
                    return CKR_ATTRIBUTE_VALUE_INVALID
        _write_ulong(phObject, FAKE_KEY_HANDLE)
        return CKR_OK

    def C_CopyObject(self, hSession, hObject, pTemplate, ulCount, phNewObject) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if hObject != FAKE_KEY_HANDLE:
            return CKR_OBJECT_HANDLE_INVALID
        if not phNewObject:
            return CKR_ARGUMENTS_BAD
        _write_ulong(phNewObject, FAKE_KEY_HANDLE)
        return CKR_OK

    def C_DestroyObject(self, hSession, hObject) -> int:
        code = self._not_initialized() or self._session_guard(hSession)
        return code or CKR_OK

    def C_GetObjectSize(self, hSession, hObject, pulSize) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if hObject != FAKE_KEY_HANDLE:
            return CKR_OBJECT_HANDLE_INVALID
        if not pulSize:
            return CKR_ARGUMENTS_BAD
        _write_ulong(pulSize, 0x100)
        return CKR_OK

    def _attribute_values(self, handle: int):
        """``{attribute_type: bytes}`` for the object, or None if the handle is unknown."""
        for certificate in self.certificates():
            if handle == certificate.certificate_id:
                return self._certificate_attributes(certificate, is_key=False)
            if handle == certificate.key_handle:
                return self._certificate_attributes(certificate, is_key=True)
        return None

    def _certificate_attributes(self, certificate: Certificate, *, is_key: bool) -> dict:
        identifier = certificate.certificate_id.to_bytes(k.CKA_ID_WIDTH, "little")
        try:
            info = certificate.info
        except DerError:
            info = None
        values = {
            k.CKA_CLASS: (k.CKO_PRIVATE_KEY if is_key else k.CKO_CERTIFICATE).to_bytes(8, "little"),
            k.CKA_TOKEN: b"\x01",
            k.CKA_PRIVATE: b"\x01" if is_key else b"\x00",
            k.CKA_LABEL: info.label.encode() if info else b"",
            k.CKA_CERTIFICATE_TYPE: k.CKC_X_509.to_bytes(8, "little"),
            k.CKA_KEY_TYPE: k.CKK_RSA.to_bytes(8, "little"),
            k.CKA_ID: identifier,
            k.CKA_SENSITIVE: b"\x01",
            k.CKA_VALUE: b"" if is_key else certificate.raw,
        }
        if info is not None:
            values[k.CKA_SUBJECT] = info.subject
            values[k.CKA_ISSUER] = info.issuer
            values[k.CKA_SERIAL_NUMBER] = info.serial
            # The modulus comes from the certificate for either handle.
            values[k.CKA_MODULUS] = info.modulus
        return values

    def C_GetAttributeValue(self, hSession, hObject, pTemplate, ulCount) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if not pTemplate or not ulCount:
            return CKR_ARGUMENTS_BAD
        values = self._attribute_values(hObject)
        if values is None:
            return CKR_OBJECT_HANDLE_INVALID

        result = CKR_OK
        for index in range(ulCount):
            base = pTemplate + index * 24
            attribute_type = _read_ulong(base)
            buffer = _read_ulong(base + 8)
            length = _read_ulong(base + 16)
            available = values.get(attribute_type)
            if available is None:
                # An unsupported attribute type is reported and the length is left alone.
                trace(
                    f"  attribute {attribute_type:#06x} (unsupported) rc={CKR_ATTRIBUTE_TYPE_INVALID:#x}"
                )
                result = CKR_ATTRIBUTE_TYPE_INVALID
                continue
            trace(f"  attribute {attribute_type:#06x} len={len(available)}")
            if not buffer:
                _write_ulong(base + 16, len(available))
                continue
            if length < len(available):
                _write_ulong(base + 16, len(available))
                result = CKR_BUFFER_TOO_SMALL
                continue
            _write(buffer, available)
            _write_ulong(base + 16, len(available))
        return result

    def C_SetAttributeValue(self, hSession, hObject, pTemplate, ulCount) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if hObject != FAKE_KEY_HANDLE:
            return CKR_OBJECT_HANDLE_INVALID
        if pTemplate and ulCount:
            for index in range(ulCount):
                if _read_ulong(pTemplate + index * 24) != 0:
                    return CKR_ATTRIBUTE_TYPE_INVALID
        return CKR_OK

    # --- searching ------------------------------------------------------------------
    def C_FindObjectsInit(self, hSession, pTemplate, ulCount) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation:
            return CKR_OPERATION_ACTIVE
        code = self._session_guard(hSession)
        if code:
            return code
        if not pTemplate:
            return CKR_ARGUMENTS_BAD

        self._find_code = FIND_NO_FILTER
        self._find_id = None
        self._find_issuer = None
        self._find_subject = None
        self._find_value = None

        for index in range(ulCount):
            base = pTemplate + index * 24
            attribute_type = _read_ulong(base)
            buffer = _read_ulong(base + 8)
            length = _read_ulong(base + 16)
            if not buffer or not length:
                return CKR_ATTRIBUTE_VALUE_INVALID

            if trace_enabled():
                # Guarded on purpose: the f-string dereferences caller memory, which must
                # not happen when tracing is off.
                trace(
                    f"  find template {attribute_type:#06x} len={length} "
                    f"value={_read(buffer, length).hex()}"
                )

            if attribute_type == k.CKA_CLASS:
                if length != 8:
                    return CKR_ATTRIBUTE_VALUE_INVALID
                value = _read_ulong(buffer)
                mapped = FIND_CLASS_CODES.get(value)
                if mapped is None:
                    self.config.log(
                        f"Tipo de classe nao tratado em C_FindObjectsInit: {value:#8x}"
                    )
                    self._find_code = 0  # matches nothing
                else:
                    self._find_code = mapped
            elif attribute_type == k.CKA_ID:
                self._find_id = _read_ulong(buffer)
            elif attribute_type == k.CKA_ISSUER:
                self._find_issuer = _read(buffer, length)
            elif attribute_type == k.CKA_SUBJECT:
                self._find_subject = _read(buffer, length)
            elif attribute_type == k.CKA_VALUE:
                self._find_value = _read(buffer, length)
            elif attribute_type in (k.CKA_CERTIFICATE_TYPE, k.CKA_TOKEN):
                pass  # accepted and ignored
            else:
                self.config.log(
                    f"Tipo de atributo nao tratado em C_FindObjectsInit: {attribute_type:#8x}"
                )
                return CKR_ATTRIBUTE_TYPE_INVALID

        self.operation = OP_FIND
        self._find_exhausted = False
        return CKR_OK

    def _find_handles(self) -> list[int]:
        """Handles the current template matches, in a fixed order.

        The rules:

        * only class codes 4 (private key), 5 (certificate) and 100 (no class in the template)
          ever match anything;
        * with a ``CKA_ID`` filter exactly one handle comes back, the value itself -- the id
          is not even checked against the directory, so an unknown id still yields a handle;
        * ``CKA_SUBJECT``/``CKA_ISSUER`` matches report a certificate *and* a key handle when
          the template carried no class, ``CKA_VALUE`` matches report only the certificate.
        """
        code = self._find_code
        if code not in (FIND_CERTIFICATE, FIND_NO_FILTER, FIND_PRIVATE_KEY):
            return []

        certificates = self.certificates()
        if self._find_issuer is not None:
            return self._handles_for(certificates, "issuer", self._find_issuer, both=True)
        if self._find_subject is not None:
            return self._handles_for(certificates, "subject", self._find_subject, both=True)
        if self._find_value is not None:
            return self._handles_for(certificates, "value", self._find_value, both=False)
        if self._find_id:
            if code == FIND_PRIVATE_KEY:
                return [(self._find_id + k.KEY_HANDLE_FLAG) & 0xFFFFFFFF]
            return [self._find_id & 0xFFFFFFFF]
        return self._handles_for(certificates, None, None, both=True)

    def _handles_for(self, certificates, name, wanted, *, both: bool) -> list[int]:
        code = self._find_code
        handles: list[int] = []
        for certificate in certificates:
            if name is not None and self._certificate_bytes(certificate, name) != wanted:
                continue
            if code in (FIND_CERTIFICATE, FIND_NO_FILTER):
                handles.append(certificate.certificate_id)
            if code == FIND_PRIVATE_KEY or (code == FIND_NO_FILTER and both):
                handles.append(certificate.key_handle)
        return handles

    @staticmethod
    def _certificate_bytes(certificate: Certificate, name: str) -> bytes:
        if name == "value":
            return certificate.raw
        try:
            info = certificate.info
        except DerError:
            return b""
        return getattr(info, name)

    def C_FindObjects(self, hSession, phObject, ulMaxObjectCount, pulObjectCount) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_FIND:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if (not phObject and ulMaxObjectCount) or not pulObjectCount:
            return CKR_ARGUMENTS_BAD
        _write_ulong(pulObjectCount, 0)
        if self._find_exhausted:
            return CKR_OK

        # The search is marked exhausted after one call, so results beyond ulMaxObjectCount are
        # dropped rather than returned on the next call.
        self._find_exhausted = True
        if ulMaxObjectCount == 0:
            return CKR_OK

        handles = self._find_handles()[:ulMaxObjectCount]
        for index, handle in enumerate(handles):
            _write_ulong(phObject + index * 8, handle)
        _write_ulong(pulObjectCount, len(handles))
        return CKR_OK

    def C_FindObjectsFinal(self, hSession) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_FIND:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        self._reset_operation()
        self._find_results = []
        self._find_index = 0
        return CKR_OK

    # --- signing --------------------------------------------------------------------
    def C_SignInit(self, hSession, pMechanism, hKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation & ~0x2:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism:
            return CKR_ARGUMENTS_BAD

        mechanism = _read_ulong(pMechanism)
        parameter = _read_ulong(pMechanism + 8)
        parameter_len = _read_ulong(pMechanism + 16)
        self.pss = None

        if mechanism == k.CKM_RSA_PKCS:
            if parameter or parameter_len:
                return CKR_MECHANISM_PARAM_INVALID
            if hKey <= 0x7FFFFFFF:
                return CKR_KEY_TYPE_INCONSISTENT
        elif mechanism == k.CKM_RSA_PKCS_PSS:
            if hKey <= 0x7FFFFFFF:
                return CKR_KEY_TYPE_INCONSISTENT
            if parameter or parameter_len:
                if parameter_len < 24:
                    return CKR_MECHANISM_PARAM_INVALID
                self.pss = PssParams(
                    hash_alg=_read_ulong(parameter),
                    mgf=_read_ulong(parameter + 8),
                    salt_len=_read_ulong(parameter + 16),
                )
        else:
            self.config.log(f"Mecanismo invalido: {mechanism:#x}")
            return CKR_MECHANISM_INVALID

        self.certificate_id = hKey - k.KEY_HANDLE_FLAG
        self.mechanism = mechanism
        self.operation = OP_SIGN_ENCRYPT if self.operation else OP_SIGN
        return CKR_OK

    def C_Sign(self, hSession, pData, ulDataLen, pSignature, pulSignatureLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_SIGN:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pulSignatureLen or not pData or not ulDataLen:
            return CKR_ARGUMENTS_BAD
        if not pSignature:
            # Size query: no network activity, operation stays active.
            _write_ulong(pulSignatureLen, k.SIGNATURE_LENGTH)
            return CKR_OK
        if self.certificate_id is None:
            _write_ulong(pulSignatureLen, k.SIGNATURE_LENGTH)
            return CKR_FUNCTION_FAILED

        data = _read(pData, ulDataLen)
        if ulDataLen > MAX_SIGNATURE_PAYLOAD:
            # A signing request carries a digest-sized payload; refuse an oversized one here
            # rather than putting it on the wire.
            _write_ulong(pulSignatureLen, k.SIGNATURE_LENGTH)
            return CKR_ARGUMENTS_BAD
        try:
            signature = self.client().sign(self.certificate_id, data, pss=self.pss)
        except SerproIDError as exc:
            _write_ulong(pulSignatureLen, k.SIGNATURE_LENGTH)
            return exc.ckr
        except Exception:
            _write_ulong(pulSignatureLen, k.SIGNATURE_LENGTH)
            return CKR_FUNCTION_FAILED

        if len(signature) > _read_ulong(pulSignatureLen):
            # The caller's buffer is smaller than the signature: report the size it needs and
            # write nothing. Never write past what the caller declared.
            _write_ulong(pulSignatureLen, len(signature))
            return CKR_BUFFER_TOO_SMALL
        _write(pSignature, signature)
        _write_ulong(pulSignatureLen, k.SIGNATURE_LENGTH)
        self._reset_operation()
        return CKR_OK

    def C_SignUpdate(self, hSession, pPart, ulPartLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_SIGN:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pPart or not ulPartLen:
            return CKR_ARGUMENTS_BAD
        return CKR_OK  # accepted and ignored

    def C_SignFinal(self, hSession, pSignature, pulSignatureLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation not in (OP_SIGN, OP_SIGN_ENCRYPT):
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pulSignatureLen:
            return CKR_ARGUMENTS_BAD
        self.operation = OP_NONE
        return CKR_FUNCTION_NOT_SUPPORTED

    def C_SignRecoverInit(self, hSession, pMechanism, hKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation:
            return CKR_OPERATION_ACTIVE
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism or _read_ulong(pMechanism) != k.CKM_RSA_PKCS:
            return CKR_MECHANISM_INVALID
        self.operation = OP_SIGN_RECOVER
        return CKR_OK

    def C_SignRecover(self, hSession, pData, ulDataLen, pSignature, pulSignatureLen) -> int:
        return self._cipher(hSession, OP_SIGN_RECOVER, pData, ulDataLen, pSignature, pulSignatureLen)

    # --- ciphers --------------------------------------------------------------------
    def _cipher(self, hSession, expected, pIn, ulInLen, pOut, pulOutLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != expected:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pulOutLen or not ulInLen or not pIn:
            return CKR_ARGUMENTS_BAD
        self.operation = OP_NONE
        return CKR_FUNCTION_NOT_SUPPORTED

    def C_EncryptInit(self, hSession, pMechanism, hKey) -> int:
        return self._cipher_init(hSession, pMechanism, hKey, OP_ENCRYPT, required_usage=0x100)

    def C_DecryptInit(self, hSession, pMechanism, hKey) -> int:
        return self._cipher_init(hSession, pMechanism, hKey, OP_DECRYPT, required_usage=0x200)

    def _cipher_init(self, hSession, pMechanism, hKey, operation, *, required_usage) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation in (OP_ENCRYPT, OP_DECRYPT):
            return CKR_OPERATION_ACTIVE
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism:
            return CKR_ARGUMENTS_BAD
        mechanism = _read_ulong(pMechanism)
        parameter = _read_ulong(pMechanism + 8)
        parameter_len = _read_ulong(pMechanism + 16)

        if mechanism == k.CKM_RSA_PKCS:
            if parameter or parameter_len:
                return CKR_MECHANISM_PARAM_INVALID
        elif mechanism == k.CKM_RSA_PKCS_OAEP:
            if parameter_len != 0x28:
                return CKR_MECHANISM_PARAM_INVALID
        elif mechanism == k.CKM_DES3_CBC:
            if parameter_len != 8:
                return CKR_MECHANISM_PARAM_INVALID
        elif mechanism == k.CKM_AES_CBC:
            if parameter_len != 0x10:
                return CKR_MECHANISM_PARAM_INVALID
        else:
            return CKR_MECHANISM_INVALID

        if hKey == FAKE_KEY_HANDLE:
            return CKR_KEY_TYPE_INCONSISTENT
        self.operation = OP_DIGEST_ENCRYPT if self.operation == OP_DIGEST else operation
        return CKR_OK

    def C_Encrypt(self, hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen) -> int:
        code = self._cipher(hSession, OP_ENCRYPT, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen)
        if code == CKR_OK:
            self.operation = OP_NONE
        return code

    def C_EncryptUpdate(self, hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen) -> int:
        return self._cipher(hSession, OP_ENCRYPT, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)

    def C_Decrypt(self, hSession, pData, ulDataLen, pDecryptedData, pulDecryptedDataLen) -> int:
        code = self._cipher(hSession, OP_DECRYPT, pData, ulDataLen, pDecryptedData, pulDecryptedDataLen)
        if code == CKR_OK:
            self.operation = OP_NONE
        return code

    def C_DecryptUpdate(self, hSession, pPart, ulPartLen, pDecryptedPart, pulDecryptedPartLen) -> int:
        return self._cipher(hSession, OP_DECRYPT, pPart, ulPartLen, pDecryptedPart, pulDecryptedPartLen)

    def C_EncryptFinal(self, hSession, pLastEncryptedPart, pulLastEncryptedPartLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation not in (OP_ENCRYPT, OP_DIGEST_ENCRYPT, OP_SIGN_ENCRYPT):
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pulLastEncryptedPartLen:
            return CKR_ARGUMENTS_BAD
        _write_ulong(pulLastEncryptedPartLen, 0)
        self.operation = OP_NONE
        return CKR_OK

    def C_DecryptFinal(self, hSession, pLastPart, pulLastPartLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation not in (OP_DECRYPT, OP_DIGEST_DECRYPT, OP_DECRYPT_VERIFY):
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pulLastPartLen:
            return CKR_ARGUMENTS_BAD
        _write_ulong(pulLastPartLen, 0)
        self.operation = OP_NONE
        return CKR_OK

    def C_DigestEncryptUpdate(self, hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen) -> int:
        return self._cipher(hSession, OP_DIGEST_ENCRYPT, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)

    def C_DecryptDigestUpdate(self, hSession, pPart, ulPartLen, pDecryptedPart, pulDecryptedPartLen) -> int:
        return self._cipher(hSession, OP_DIGEST_DECRYPT, pPart, ulPartLen, pDecryptedPart, pulDecryptedPartLen)

    def C_SignEncryptUpdate(self, hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen) -> int:
        return self._cipher(hSession, OP_SIGN_ENCRYPT, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)

    def C_DecryptVerifyUpdate(self, hSession, pPart, ulPartLen, pDecryptedPart, pulDecryptedPartLen) -> int:
        return self._cipher(hSession, OP_DECRYPT_VERIFY, pPart, ulPartLen, pDecryptedPart, pulDecryptedPartLen)

    # --- digests --------------------------------------------------------------------
    def C_DigestInit(self, hSession, pMechanism) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation:
            return CKR_OPERATION_ACTIVE
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism:
            return CKR_ARGUMENTS_BAD
        if _read_ulong(pMechanism) != k.CKM_SHA_1 or _read_ulong(pMechanism + 8):
            return CKR_MECHANISM_INVALID
        self.operation = OP_DIGEST
        return CKR_OK

    def _digest(self, hSession, pDigest, pulDigestLen, *, clear: bool) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_DIGEST:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pulDigestLen:
            return CKR_ARGUMENTS_BAD
        self.operation = OP_NONE
        return CKR_FUNCTION_NOT_SUPPORTED

    def C_Digest(self, hSession, pData, ulDataLen, pDigest, pulDigestLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_DIGEST:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pData or not ulDataLen:
            return CKR_ARGUMENTS_BAD
        return self._digest(hSession, pDigest, pulDigestLen, clear=True)

    def C_DigestUpdate(self, hSession, pPart, ulPartLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_DIGEST:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pPart or not ulPartLen:
            return CKR_ARGUMENTS_BAD
        return CKR_OK

    def C_DigestKey(self, hSession, hKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_DIGEST:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        return CKR_OK if hKey == FAKE_KEY_HANDLE_2 else CKR_OBJECT_HANDLE_INVALID

    def C_DigestFinal(self, hSession, pDigest, pulDigestLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation not in (OP_DIGEST, OP_DIGEST_ENCRYPT, OP_DIGEST_DECRYPT):
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        previous = self.operation
        self.operation = OP_DIGEST
        result = self._digest(hSession, pDigest, pulDigestLen, clear=False)
        if result != CKR_OK:
            self.operation = previous
            return result
        self.operation = {OP_DIGEST_ENCRYPT: OP_ENCRYPT, OP_DIGEST_DECRYPT: OP_DECRYPT}.get(previous, OP_NONE)
        return CKR_OK

    # --- verification ---------------------------------------------------------------
    def C_VerifyInit(self, hSession, pMechanism, hKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation not in (OP_NONE, OP_DECRYPT):
            return CKR_OPERATION_ACTIVE
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism or _read_ulong(pMechanism) not in (k.CKM_RSA_PKCS, k.CKM_SHA1_RSA_PKCS):
            return CKR_MECHANISM_INVALID
        if _read_ulong(pMechanism + 8):
            return CKR_MECHANISM_PARAM_INVALID
        self.operation = OP_DECRYPT_VERIFY if self.operation == OP_DECRYPT else OP_VERIFY
        return CKR_OK

    def _verify(self, hSession, pSignature, ulSignatureLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation not in (OP_VERIFY, OP_DECRYPT_VERIFY):
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        self.operation = OP_NONE
        return CKR_FUNCTION_NOT_SUPPORTED

    def C_Verify(self, hSession, pData, ulDataLen, pSignature, ulSignatureLen) -> int:
        code = self._verify(hSession, pSignature, ulSignatureLen)
        if code in (CKR_OK, CKR_SIGNATURE_INVALID):
            self.operation = OP_NONE
        return code

    def C_VerifyUpdate(self, hSession, pPart, ulPartLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation != OP_VERIFY:
            return CKR_OPERATION_NOT_INITIALIZED
        code = self._session_guard(hSession)
        if code:
            return code
        if not pPart or not ulPartLen:
            return CKR_ARGUMENTS_BAD
        return CKR_OK

    def C_VerifyFinal(self, hSession, pSignature, ulSignatureLen) -> int:
        return self._verify(hSession, pSignature, ulSignatureLen)

    def C_VerifyRecoverInit(self, hSession, pMechanism, hKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        if self.operation:
            return CKR_OPERATION_ACTIVE
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism or _read_ulong(pMechanism) != k.CKM_RSA_PKCS:
            return CKR_MECHANISM_INVALID
        self.operation = OP_VERIFY_RECOVER
        return CKR_OK

    def C_VerifyRecover(self, hSession, pSignature, ulSignatureLen, pData, pulDataLen) -> int:
        return self._cipher(hSession, OP_VERIFY_RECOVER, pSignature, ulSignatureLen, pData, pulDataLen)

    # --- key management (not supported) ------------------------------------------------------
    def C_GenerateKey(self, hSession, pMechanism, pTemplate, ulCount, phKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism or _read_ulong(pMechanism) != k.CKM_DES3_KEY_GEN:
            return CKR_MECHANISM_INVALID
        if not phKey:
            return CKR_ARGUMENTS_BAD
        if pTemplate and ulCount:
            for index in range(ulCount):
                base = pTemplate + index * 24
                if not _read_ulong(base + 8) or not _read_ulong(base + 16):
                    return CKR_ATTRIBUTE_VALUE_INVALID
        _write_ulong(phKey, FAKE_KEY_HANDLE_2)
        return CKR_OK

    def C_GenerateKeyPair(self, hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount,
                          pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey) -> int:
        return CKR_FUNCTION_NOT_SUPPORTED

    def C_WrapKey(self, hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism or _read_ulong(pMechanism) != k.CKM_RSA_PKCS or _read_ulong(pMechanism + 8):
            return CKR_MECHANISM_INVALID
        if hKey != FAKE_KEY_HANDLE_2 or hWrappingKey != FAKE_WRAPPING_KEY_HANDLE:
            return CKR_KEY_HANDLE_INVALID
        if not pulWrappedKeyLen:
            return CKR_ARGUMENTS_BAD
        self.operation = OP_NONE
        return CKR_FUNCTION_NOT_SUPPORTED

    def C_UnwrapKey(self, hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen,
                    pTemplate, ulAttributeCount, phKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism or _read_ulong(pMechanism) != k.CKM_RSA_PKCS:
            return CKR_MECHANISM_INVALID
        if hUnwrappingKey != FAKE_UNWRAPPING_KEY_HANDLE:
            return CKR_KEY_HANDLE_INVALID
        if not phKey:
            return CKR_ARGUMENTS_BAD
        if pTemplate and ulAttributeCount:
            for index in range(ulAttributeCount):
                base = pTemplate + index * 24
                if not _read_ulong(base + 8) or not _read_ulong(base + 16):
                    return CKR_ATTRIBUTE_VALUE_INVALID
        _write_ulong(phKey, FAKE_KEY_HANDLE_2)
        return CKR_OK

    def C_DeriveKey(self, hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if not pMechanism:
            return CKR_ARGUMENTS_BAD
        if _read_ulong(pMechanism) != k.CKM_X9_42_DH_DERIVE or _read_ulong(pMechanism + 16) != 0x10:
            return CKR_MECHANISM_PARAM_INVALID
        if hBaseKey != FAKE_KEY_HANDLE_2:
            return CKR_OBJECT_HANDLE_INVALID
        if not phKey:
            return CKR_ARGUMENTS_BAD
        _write_ulong(phKey, FAKE_KEY_HANDLE_2)
        return CKR_OK

    # --- random ---------------------------------------------------------------------
    def C_SeedRandom(self, hSession, pSeed, ulSeedLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        return CKR_OK if pSeed and ulSeedLen else CKR_ARGUMENTS_BAD

    def C_GenerateRandom(self, hSession, pRandomData, ulRandomLen) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        if code:
            return code
        if not pRandomData:
            return CKR_ARGUMENTS_BAD
        _write(pRandomData, os.urandom(ulRandomLen))
        return CKR_OK

    # --- misc -----------------------------------------------------------------------
    def C_GetFunctionStatus(self, hSession) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        return code or CKR_FUNCTION_NOT_PARALLEL

    def C_CancelFunction(self, hSession) -> int:
        code = self._not_initialized()
        if code:
            return code
        code = self._session_guard(hSession)
        return code or CKR_FUNCTION_NOT_PARALLEL

    def C_WaitForSlotEvent(self, flags, pSlot, pReserved) -> int:
        code = self._not_initialized()
        if code:
            return code
        return 8  # CKR_NO_EVENT

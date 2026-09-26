"""PKCS#11 return values and the exception hierarchy that carries them.

Every failure path in the core raises a :class:`SerproIDError` whose ``ckr`` attribute is
the exact ``CKR_*`` value the official module returns for the same condition. The PKCS#11
binding therefore never re-derives error codes: it just reads ``err.ckr``.
"""

from __future__ import annotations

# --- CKR_* (PKCS#11 v2.40) --------------------------------------------------------
CKR_OK = 0x00000000
CKR_CANCEL = 0x00000001
CKR_SLOT_ID_INVALID = 0x00000003
CKR_FUNCTION_FAILED = 0x00000006
CKR_ARGUMENTS_BAD = 0x00000007
CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013
CKR_FUNCTION_CANCELED = 0x00000050
CKR_FUNCTION_NOT_PARALLEL = 0x00000051
CKR_FUNCTION_NOT_SUPPORTED = 0x00000054
CKR_KEY_HANDLE_INVALID = 0x00000060
CKR_KEY_TYPE_INCONSISTENT = 0x00000063
CKR_MECHANISM_INVALID = 0x00000070
CKR_MECHANISM_PARAM_INVALID = 0x00000071
CKR_OBJECT_HANDLE_INVALID = 0x00000082
CKR_OPERATION_ACTIVE = 0x00000090
CKR_OPERATION_NOT_INITIALIZED = 0x00000091
CKR_USER_NOT_LOGGED_IN = 0x00000101
CKR_BUFFER_TOO_SMALL = 0x00000150
CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CKR_SESSION_HANDLE_INVALID = 0x000000B3
CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4
CKR_SIGNATURE_INVALID = 0x000000C0
CKR_SIGNATURE_LEN_RANGE = 0x000000C1
CKR_TOKEN_NOT_PRESENT = 0x000000E0

CKR_NAMES = {
    value: name for name, value in list(globals().items()) if name.startswith("CKR_")
}


class SerproIDError(Exception):
    """Any failure, carrying the ``CKR_*`` value the original module would return."""

    ckr: int = CKR_FUNCTION_FAILED

    def __init__(self, message: str, ckr: int | None = None) -> None:
        super().__init__(message)
        if ckr is not None:
            self.ckr = ckr

    @property
    def ckr_name(self) -> str:
        return CKR_NAMES.get(self.ckr, f"CKR_0x{self.ckr:X}")


class TransportError(SerproIDError):
    """DNS/TCP/TLS failure. The original maps all of these to ``CKR_FUNCTION_FAILED``."""

    ckr = CKR_FUNCTION_FAILED


class BackendError(SerproIDError):
    """The backend replied, but the exchange failed. Also ``CKR_FUNCTION_FAILED``."""

    ckr = CKR_FUNCTION_FAILED


class AuthorizationCanceled(SerproIDError):
    """The user refused on the phone, or the 20-poll window elapsed."""

    ckr = CKR_FUNCTION_CANCELED

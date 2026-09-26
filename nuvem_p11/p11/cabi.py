"""ctypes binding: turns :class:`~nuvem_p11.p11.module.Token` into a real ``CK_FUNCTION_LIST``.

Keeping the 68 signatures in one declarative table (rather than hand-written C wrappers)
means the entire PKCS#11 surface is exercisable from Python without a compiler. The table
*order* is the one the spec mandates for ``CK_FUNCTION_LIST``; ``tests/test_p11_abi.py``
verifies both the count and the field offsets against NSS's ``pkcs11t.h``, so a mistake
here cannot silently survive.
"""

from __future__ import annotations

import ctypes

from .constants import CRYPTOKI_VERSION
from .module import Token
from .trace import describe, enabled as trace_enabled, trace

CK_RV = ctypes.c_ulong
CK_ULONG = ctypes.c_ulong
CK_BYTE_PTR = ctypes.c_void_p
CK_VOID_PTR = ctypes.c_void_p
CK_FLAGS = ctypes.c_ulong

#: ``(name, argtypes)`` in exact ``CK_FUNCTION_LIST`` order.
SIGNATURES: tuple[tuple[str, tuple], ...] = (
    ("C_Initialize", (CK_VOID_PTR,)),
    ("C_Finalize", (CK_VOID_PTR,)),
    ("C_GetInfo", (CK_VOID_PTR,)),
    ("C_GetFunctionList", (CK_VOID_PTR,)),
    ("C_GetSlotList", (ctypes.c_ubyte, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_GetSlotInfo", (CK_ULONG, CK_VOID_PTR)),
    ("C_GetTokenInfo", (CK_ULONG, CK_VOID_PTR)),
    ("C_GetMechanismList", (CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_GetMechanismInfo", (CK_ULONG, CK_ULONG, CK_VOID_PTR)),
    ("C_InitToken", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR)),
    ("C_InitPIN", (CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_SetPIN", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_OpenSession", (CK_ULONG, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, CK_BYTE_PTR)),
    ("C_CloseSession", (CK_ULONG,)),
    ("C_CloseAllSessions", (CK_ULONG,)),
    ("C_GetSessionInfo", (CK_ULONG, CK_VOID_PTR)),
    ("C_GetOperationState", (CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_SetOperationState", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_ULONG)),
    ("C_Login", (CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_Logout", (CK_ULONG,)),
    ("C_CreateObject", (CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR)),
    ("C_CopyObject", (CK_ULONG, CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR)),
    ("C_DestroyObject", (CK_ULONG, CK_ULONG)),
    ("C_GetObjectSize", (CK_ULONG, CK_ULONG, CK_BYTE_PTR)),
    ("C_GetAttributeValue", (CK_ULONG, CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_SetAttributeValue", (CK_ULONG, CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_FindObjectsInit", (CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_FindObjects", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR)),
    ("C_FindObjectsFinal", (CK_ULONG,)),
    ("C_EncryptInit", (CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_Encrypt", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_EncryptUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_EncryptFinal", (CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_DecryptInit", (CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_Decrypt", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_DecryptUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_DecryptFinal", (CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_DigestInit", (CK_ULONG, CK_VOID_PTR)),
    ("C_Digest", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_DigestUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_DigestKey", (CK_ULONG, CK_ULONG)),
    ("C_DigestFinal", (CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_SignInit", (CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_Sign", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_SignUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_SignFinal", (CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_SignRecoverInit", (CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_SignRecover", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_VerifyInit", (CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_Verify", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_VerifyUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_VerifyFinal", (CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_VerifyRecoverInit", (CK_ULONG, CK_VOID_PTR, CK_ULONG)),
    ("C_VerifyRecover", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_DigestEncryptUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_DecryptDigestUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_SignEncryptUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_DecryptVerifyUpdate", (CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    ("C_GenerateKey", (CK_ULONG, CK_VOID_PTR, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR)),
    (
        "C_GenerateKeyPair",
        (CK_ULONG, CK_VOID_PTR, CK_VOID_PTR, CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR),
    ),
    ("C_WrapKey", (CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_BYTE_PTR)),
    (
        "C_UnwrapKey",
        (CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR),
    ),
    ("C_DeriveKey", (CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_BYTE_PTR)),
    ("C_SeedRandom", (CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_GenerateRandom", (CK_ULONG, CK_BYTE_PTR, CK_ULONG)),
    ("C_GetFunctionStatus", (CK_ULONG,)),
    ("C_CancelFunction", (CK_ULONG,)),
    ("C_WaitForSlotEvent", (CK_FLAGS, CK_BYTE_PTR, CK_VOID_PTR)),
)

if len(SIGNATURES) != 68:  # pragma: no cover - guards the table above
    raise AssertionError(f"CK_FUNCTION_LIST needs 68 entries, got {len(SIGNATURES)}")

FUNCTION_NAMES = tuple(name for name, _ in SIGNATURES)

#: ``sizeof(CK_FUNCTION_LIST)``: the ``CK_VERSION`` (2 bytes + 6 of padding) plus 68 pointers.
FUNCTION_LIST_SIZE = 8 + 68 * ctypes.sizeof(ctypes.c_void_p)


class _Version(ctypes.Structure):
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class FunctionList(ctypes.Structure):
    """Binary layout of ``CK_FUNCTION_LIST``: ``CK_VERSION`` then 68 pointers."""

    _fields_ = [("version", _Version)] + [(name, ctypes.c_void_p) for name in FUNCTION_NAMES]


class Binding:
    """Owns the callbacks and the ``CK_FUNCTION_LIST`` instance for one :class:`Token`."""

    def __init__(self, token: Token) -> None:
        self.token = token
        # A PKCS#11 loader keeps the raw pointer returned by C_GetFunctionList forever, so the
        # table and its callbacks must outlive every use. Anchoring ourselves to the token
        # makes the two lifetimes the same, which removes a use-after-free footgun.
        token.binding = self
        self._callbacks: dict[str, object] = {}
        self.function_list = FunctionList()
        self.function_list.version.major, self.function_list.version.minor = CRYPTOKI_VERSION
        for name, argtypes in SIGNATURES:
            # C_GetFunctionList is not dispatched to the token: it has to hand back this very
            # table, so it is installed at the end of the constructor.
            if name == "C_GetFunctionList":
                continue
            callback = ctypes.CFUNCTYPE(CK_RV, *argtypes)(self._dispatch(name))
            self._callbacks[name] = callback
            setattr(self.function_list, name, ctypes.cast(callback, ctypes.c_void_p))
        self._callbacks["C_GetFunctionList"] = ctypes.CFUNCTYPE(CK_RV, CK_VOID_PTR)(
            self._get_function_list
        )
        setattr(
            self.function_list,
            "C_GetFunctionList",
            ctypes.cast(self._callbacks["C_GetFunctionList"], ctypes.c_void_p),
        )
        missing = [name for name in FUNCTION_NAMES if not getattr(self.function_list, name)]
        if missing:  # pragma: no cover - defensive
            raise AssertionError(f"unpopulated function list entries: {missing}")

    def _dispatch(self, name: str):
        method = getattr(self.token, name)

        def call(*args):
            try:
                result = int(method(*args))
            except Exception:  # never let a Python exception escape into the caller
                result = 0x5  # CKR_GENERAL_ERROR
            if trace_enabled():
                rendered = ", ".join(describe(argument) for argument in args)
                trace(f"{name}({rendered}) -> {result:#x}")
            return result

        return call

    def _get_function_list(self, ppFunctionList) -> int:
        if not ppFunctionList:
            return 0x7  # CKR_ARGUMENTS_BAD
        ctypes.c_void_p.from_address(ppFunctionList).value = ctypes.addressof(self.function_list)
        return 0

    def address(self) -> int:
        return ctypes.addressof(self.function_list)

    def symbol(self, name: str) -> int:
        """Address of one callback; used by the C shim's designated initialisers."""
        return ctypes.cast(self._callbacks[name], ctypes.c_void_p).value

    def symbol_table(self) -> dict[str, int]:
        return {name: self.symbol(name) for name in FUNCTION_NAMES}


_BINDING: Binding | None = None


def binding(token: Token | None = None) -> Binding:
    """Process-wide binding, created on first use (``C_GetFunctionList`` is a singleton)."""
    global _BINDING
    if _BINDING is None:
        _BINDING = Binding(token or Token())
    return _BINDING


def callables_at(table_address: int) -> dict:
    """Wrap a raw ``CK_FUNCTION_LIST`` address in callables.

    Used by the tools and the tests to drive any module -- ours or the official one --
    exactly the way a loader does.

    The address is raw and unowned: whoever produced it must stay alive for as long as the
    returned callables are used (a :class:`Binding` keeps itself reachable from its
    :class:`~nuvem_p11.p11.module.Token`, so the usual path is safe).
    """
    functions = {}
    for name, argtypes in SIGNATURES:
        offset = getattr(FunctionList, name).offset
        address = ctypes.c_void_p.from_address(table_address + offset).value
        if not address:
            raise AssertionError(f"{name} is NULL in the function list")
        functions[name] = ctypes.CFUNCTYPE(CK_RV, *argtypes)(address)
    return functions


def function_list_pointer() -> int:
    """Entry point used by the native shim."""
    return binding().address()


def function_symbols() -> dict[str, int]:
    return binding().symbol_table()

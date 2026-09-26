"""Canonical dump of a PKCS#11 module, for A/B comparing implementations.

Run it against the official module and against the reimplementation and diff the output:

    python3 tools/dump_module.py /usr/lib/libserproidp11.so > /tmp/original.txt
    python3 tools/dump_module.py shim/libnuvemp11.so         > /tmp/shim.txt
    diff -u /tmp/original.txt /tmp/shim.txt

Only read-only calls are made, so no signing request reaches the backend. Entry points are
resolved through ``C_GetFunctionList`` -- the standard way, and for the shim the only way,
since PKCS#11 does not require the ``C_*`` symbols to be exported individually.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys

from nuvem_p11.p11.cabi import FunctionList, callables_at

CK_RV = ctypes.c_ulong
CK_ULONG = ctypes.c_ulong


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


class SlotInfo(ctypes.Structure):
    _fields_ = [
        ("slotDescription", ctypes.c_char * 64),
        ("manufacturerID", ctypes.c_char * 32),
        ("flags", ctypes.c_ulong),
        ("hardwareVersion", Version),
        ("firmwareVersion", Version),
    ]


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


class SessionInfo(ctypes.Structure):
    _fields_ = [
        ("slotID", ctypes.c_ulong),
        ("state", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
        ("ulDeviceError", ctypes.c_ulong),
    ]


class Attribute(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ulong),
        ("pValue", ctypes.c_void_p),
        ("ulValueLen", ctypes.c_ulong),
    ]


ATTRIBUTE_NAMES = {
    0x0: "CKA_CLASS",
    0x1: "CKA_TOKEN",
    0x2: "CKA_PRIVATE",
    0x3: "CKA_LABEL",
    0x11: "CKA_VALUE",
    0x80: "CKA_CERTIFICATE_TYPE",
    0x81: "CKA_ISSUER",
    0x82: "CKA_SERIAL_NUMBER",
    0x86: "CKA_TRUSTED",
    0x87: "CKA_CERTIFICATE_CATEGORY",
    0x100: "CKA_KEY_TYPE",
    0x101: "CKA_SUBJECT",
    0x102: "CKA_ID",
    0x103: "CKA_SENSITIVE",
    0x104: "CKA_ENCRYPT",
    0x105: "CKA_DECRYPT",
    0x106: "CKA_WRAP",
    0x108: "CKA_SIGN",
    0x10A: "CKA_VERIFY",
    0x120: "CKA_MODULUS",
    0x121: "CKA_MODULUS_BITS",
    0x122: "CKA_PUBLIC_EXPONENT",
}

CLASSES = [
    (0, "CKO_DATA"),
    (1, "CKO_CERTIFICATE"),
    (2, "CKO_PUBLIC_KEY"),
    (3, "CKO_PRIVATE_KEY"),
    (4, "CKO_SECRET_KEY"),
    (5, "CKO_HW_FEATURE"),
    (6, "CKO_DOMAIN_PARAMETERS"),
    (7, "0x7"),
    (8, "0x8"),
    (9, "0x9"),
    (0xCE534350, "NSS+0"),
    (0xCE534354, "NSS+4"),
]

MECHANISM_PROBES = (0x1, 0x6, 0xD, 0x9, 0x131, 0x133, 0x220, 0x364, 0x1082, 0x2233)

ENTRIES = (
    ("C_Initialize", CK_RV, [ctypes.c_void_p]),
    ("C_GetInfo", CK_RV, [ctypes.POINTER(Info)]),
    ("C_GetSlotList", CK_RV, [ctypes.c_ubyte, ctypes.POINTER(CK_ULONG), ctypes.POINTER(CK_ULONG)]),
    ("C_GetSlotInfo", CK_RV, [CK_ULONG, ctypes.POINTER(SlotInfo)]),
    ("C_GetTokenInfo", CK_RV, [CK_ULONG, ctypes.POINTER(TokenInfo)]),
    ("C_GetMechanismList", CK_RV, [CK_ULONG, ctypes.POINTER(CK_ULONG), ctypes.POINTER(CK_ULONG)]),
    ("C_GetMechanismInfo", CK_RV, [CK_ULONG, CK_ULONG, ctypes.c_void_p]),
    (
        "C_OpenSession",
        CK_RV,
        [CK_ULONG, CK_ULONG, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(CK_ULONG)],
    ),
    ("C_Login", CK_RV, [CK_ULONG, CK_ULONG, ctypes.c_void_p, CK_ULONG]),
    ("C_Logout", CK_RV, [CK_ULONG]),
    ("C_CloseSession", CK_RV, [CK_ULONG]),
    ("C_CloseAllSessions", CK_RV, [CK_ULONG]),
    ("C_GetSessionInfo", CK_RV, [CK_ULONG, ctypes.POINTER(SessionInfo)]),
    ("C_FindObjectsInit", CK_RV, [CK_ULONG, ctypes.POINTER(Attribute), CK_ULONG]),
    (
        "C_FindObjects",
        CK_RV,
        [CK_ULONG, ctypes.POINTER(CK_ULONG), CK_ULONG, ctypes.POINTER(CK_ULONG)],
    ),
    ("C_FindObjectsFinal", CK_RV, [CK_ULONG]),
    ("C_GetAttributeValue", CK_RV, [CK_ULONG, CK_ULONG, ctypes.POINTER(Attribute), CK_ULONG]),
)


def bind(path: str) -> dict:
    """Load the module and resolve entry points through ``C_GetFunctionList``."""
    # The official module has no DT_NEEDED entries and expects the host to provide libc and
    # libgcc_s; a bare Python process has the former but not always the latter.
    ctypes.CDLL(ctypes.util.find_library("gcc_s") or "libgcc_s.so.1", mode=ctypes.RTLD_GLOBAL)
    library = ctypes.CDLL(path)

    get_list = library.C_GetFunctionList
    get_list.restype = CK_RV
    get_list.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    table = ctypes.c_void_p()
    code = get_list(ctypes.byref(table))
    if code or not table.value:
        raise SystemExit(f"C_GetFunctionList -> {code:#x}")
    return callables_at(table.value)


def find(f: dict, session: int, class_id: int) -> tuple[int, list[int]]:
    value = CK_ULONG(class_id)
    template = Attribute(0x0, ctypes.cast(ctypes.byref(value), ctypes.c_void_p), 8)
    code = f["C_FindObjectsInit"](session, ctypes.byref(template), 1)
    if code:
        return code, []
    handles = (CK_ULONG * 32)()
    count = CK_ULONG()
    f["C_FindObjects"](session, handles, 32, ctypes.byref(count))
    f["C_FindObjectsFinal"](session)
    return 0, list(handles)[: count.value]


def describe_attribute(f: dict, session: int, handle: int, attribute_type: int) -> str:
    attribute = Attribute(attribute_type, None, 0)
    code = f["C_GetAttributeValue"](session, handle, ctypes.byref(attribute), 1)
    if code:
        return f"rc={code:#x}"
    size = attribute.ulValueLen
    if size in (0, 0xFFFFFFFFFFFFFFFF):
        return f"rc=0x0 len={size}"
    buffer = (ctypes.c_ubyte * size)()
    attribute.pValue = ctypes.cast(buffer, ctypes.c_void_p)
    code = f["C_GetAttributeValue"](session, handle, ctypes.byref(attribute), 1)
    raw = bytes(buffer)
    shown = raw.hex() if size > 64 else repr(raw)
    return f"rc={code:#x} len={size} {shown}"


def raw_field(struct, name: str, size: int) -> str:
    """Raw bytes of a fixed-width field: ``repr()`` would hide everything past a NUL."""
    offset = getattr(type(struct), name).offset
    view = memoryview(struct).cast("B")
    data = bytes(view[offset : offset + size])
    return data.hex()


def find_template(f: dict, session: int, items, max_count: int = 32):
    """``C_FindObjectsInit``/``C_FindObjects`` with an arbitrary template."""
    attributes = (Attribute * len(items))()
    keepalive = []
    for index, (attribute_type, value) in enumerate(items):
        if value is None:
            attributes[index] = Attribute(attribute_type, None, 0)
            continue
        buffer = ctypes.create_string_buffer(value, len(value))
        keepalive.append(buffer)
        attributes[index] = Attribute(
            attribute_type, ctypes.cast(buffer, ctypes.c_void_p), len(value)
        )

    pointer = ctypes.cast(attributes, ctypes.POINTER(Attribute)) if items else None
    code = f["C_FindObjectsInit"](session, pointer, len(items))
    if code:
        return code, None
    handles = (CK_ULONG * max(1, max_count))()
    count = CK_ULONG()
    second = f["C_FindObjects"](session, handles, max_count, ctypes.byref(count))
    f["C_FindObjectsFinal"](session)
    return code, (second, list(handles)[: count.value])


#: Where the module looks for the ``<id>.cer`` files it serves.
CERTIFICATE_DIR = os.path.join(os.path.expanduser("~"), ".config", "serproid", "certificados")


def discover_certificate_id(directory: str = CERTIFICATE_DIR) -> int:
    """One installed certificate to probe the ``CKA_ID`` searches with.

    Read from the directory instead of hard-coded: the module serves whatever ``<id>.cer``
    files exist, so a fixed number would neither work on another machine nor be the tool's
    business to publish. ``0`` means nothing is installed and the id searches are expected
    to come back empty.
    """
    try:
        names = os.listdir(directory)
    except OSError:
        return 0
    for name in sorted(names):
        stem, _, extension = name.partition(".")
        if extension == "cer" and stem.isdigit():
            return int(stem)
    return 0


def find_templates_section(f: dict, certificate_id: int) -> None:
    """Template matrix, including the ``CKA_ID`` searches NSS uses to pair cert and key.

    This is the section that matters for client authentication: NSS finds the certificate,
    then looks up the private key by ``CKA_ID``. Returning both handles there hands back the
    certificate handle, ``C_SignInit`` refuses it and the TLS handshake fails.
    """
    session = CK_ULONG()
    f["C_OpenSession"](1, 4, None, None, ctypes.byref(session))
    handle = session.value

    identifier = certificate_id.to_bytes(8, "little")
    unknown = (424242).to_bytes(8, "little")

    def as_uint(value: int) -> bytes:
        return value.to_bytes(8, "little")

    subject = issuer = value = None
    for attribute_type, store in (
        (0x101, "subject"),
        (0x81, "issuer"),
        (0x11, "value"),
    ):
        attribute = Attribute(attribute_type, None, 0)
        if f["C_GetAttributeValue"](handle, certificate_id, ctypes.byref(attribute), 1) == 0:
            buffer = ctypes.create_string_buffer(attribute.ulValueLen)
            attribute.pValue = ctypes.cast(buffer, ctypes.c_void_p)
            f["C_GetAttributeValue"](handle, certificate_id, ctypes.byref(attribute), 1)
            if store == "subject":
                subject = buffer.raw[: attribute.ulValueLen]
            elif store == "issuer":
                issuer = buffer.raw[: attribute.ulValueLen]
            else:
                value = buffer.raw[: attribute.ulValueLen]

    print("  --- find templates ---")
    matrix = [
        ("empty", []),
        ("class DATA", [(0x0, as_uint(0))]),
        ("class SECRET", [(0x0, as_uint(4))]),
        ("class PUBKEY", [(0x0, as_uint(2))]),
        ("class CERT", [(0x0, as_uint(1))]),
        ("class PRIVKEY", [(0x0, as_uint(3))]),
        ("class unknown 0x9", [(0x0, as_uint(9))]),
        ("class NSS+4", [(0x0, as_uint(0xCE534354))]),
        ("class short len 4", [(0x0, (1).to_bytes(4, "little"))]),
        (f"PRIV + ID {certificate_id}", [(0x0, as_uint(3)), (0x102, identifier)]),
        (f"CERT + ID {certificate_id}", [(0x0, as_uint(1)), (0x102, identifier)]),
        (f"ID {certificate_id} only", [(0x102, identifier)]),
        ("ID unknown only", [(0x102, unknown)]),
        ("PRIV + ID unknown", [(0x0, as_uint(3)), (0x102, unknown)]),
        ("ID zero", [(0x102, as_uint(0))]),
        ("CKA_TOKEN", [(0x1, b"\x01")]),
        ("CKA_CERT_TYPE", [(0x80, as_uint(0))]),
        ("CKA_SUBJECT", [(0x101, subject)]),
        ("CKA_ISSUER", [(0x81, issuer)]),
        ("CKA_VALUE", [(0x11, value)]),
        ("SUBJECT + CERT", [(0x0, as_uint(1)), (0x101, subject)]),
        ("SUBJECT + PRIV", [(0x0, as_uint(3)), (0x101, subject)]),
        ("ISSUER + CERT", [(0x0, as_uint(1)), (0x81, issuer)]),
        ("ISSUER + PRIV", [(0x0, as_uint(3)), (0x81, issuer)]),
        ("VALUE + CERT", [(0x0, as_uint(1)), (0x11, value)]),
        ("VALUE + PRIV", [(0x0, as_uint(3)), (0x11, value)]),
        ("SUBJECT wrong", [(0x101, b"\x30\x00")]),
        ("ISSUER wrong", [(0x81, b"\x30\x00")]),
        ("VALUE wrong", [(0x11, b"\x30\x00")]),
        ("SUBJECT + ID", [(0x101, subject), (0x102, identifier)]),
        ("VALUE + ID", [(0x11, value), (0x102, identifier)]),
        ("unknown attr 0x9999", [(0x9999, b"\x00\x00\x00\x00")]),
        ("attr with NULL value", [(0x102, None)]),
        ("class + empty template attr", []),
    ]
    for label, items in matrix:
        code, result = find_template(f, handle, items)
        shown = "rc=%#x" % code if result is None else "init=%#x find=%#x %s" % (
            code,
            result[0],
            result[1],
        )
        print(f"  {label:<24} {shown}")
    print(
        "  maxCount smaller than results (unfiltered, max=1):",
        find_template(f, handle, [], max_count=1)[1],
    )
    f["C_CloseAllSessions"](1)


def session_state(f: dict, session: int) -> str:
    info = SessionInfo()
    code = f["C_GetSessionInfo"](session, ctypes.byref(info))
    if code:
        return f"rc={code:#x}"
    return f"rc=0x0 slot={info.slotID:#x} state={info.state:#x} flags={info.flags:#x}"


def sessions_section(f: dict) -> None:
    """Session lifecycle, including the open/open/close pattern NSS uses.

    Clearing the session-open flag in C_CloseSession breaks everything after this sequence,
    which is why it is part of the A/B dump rather than only of the unit tests.
    """
    session = CK_ULONG()
    print("  --- sessions ---")
    print("  open(RO):", hex(f["C_OpenSession"](1, 4, None, None, ctypes.byref(session))), "h=", session.value)
    print("  info   :", session_state(f, session.value))
    print("  login(USER):", hex(f["C_Login"](session.value, 1, None, 0)))
    print("  info   :", session_state(f, session.value))
    print("  login(USER) again:", hex(f["C_Login"](session.value, 1, None, 0)))
    print("  login(SO):", hex(f["C_Login"](session.value, 0, None, 0)))
    print("  logout :", hex(f["C_Logout"](session.value)))
    print("  info   :", session_state(f, session.value))

    second = CK_ULONG()
    print("  open(RO) 2nd:", hex(f["C_OpenSession"](1, 4, None, None, ctypes.byref(second))))
    code, handles = find(f, session.value, 1)
    print("  find after 2 opens:", hex(code), handles)
    print("  close one session:", hex(f["C_CloseSession"](session.value)))
    print("  info after close :", session_state(f, session.value))
    code, handles = find(f, session.value, 1)
    print("  find after close :", hex(code), handles)
    print("  find again       :", hex(find(f, session.value, 1)[0]))

    print("  close all:", hex(f["C_CloseAllSessions"](1)))
    print("  info after close all:", session_state(f, session.value))
    print("  find after close all:", hex(find(f, session.value, 1)[0]))
    print("  close session with no session open:", hex(f["C_CloseSession"](999)))
    print("  close all bad slot:", hex(f["C_CloseAllSessions"](2)))
    print("  open bad slot:", hex(f["C_OpenSession"](2, 4, None, None, ctypes.byref(session))))
    print("  open without CKF_SERIAL_SESSION:", hex(f["C_OpenSession"](1, 2, None, None, ctypes.byref(session))))
    print("  open RW:", hex(f["C_OpenSession"](1, 6, None, None, ctypes.byref(session))))
    print("  info RW:", session_state(f, session.value))
    print("  close all again:", hex(f["C_CloseAllSessions"](1)))

    print("  --- login matrix ---")
    for label, flags in (("RO", 4), ("RW", 6)):
        for user, user_name in ((0, "SO"), (1, "USER"), (2, "CTX")):
            f["C_CloseAllSessions"](1)
            sid = CK_ULONG()
            f["C_OpenSession"](1, flags, None, None, ctypes.byref(sid))
            before = session_state(f, sid.value)
            code = f["C_Login"](sid.value, user, None, 0)
            print(
                f"  {label} fresh {before} login({user_name}) -> {code:#x} now {session_state(f, sid.value)}"
            )
    for label, flags, user, user_name in (("RO", 4, 1, "USER"), ("RW", 6, 1, "USER")):
        f["C_CloseAllSessions"](1)
        sid = CK_ULONG()
        f["C_OpenSession"](1, flags, None, None, ctypes.byref(sid))
        f["C_Login"](sid.value, user, None, 0)
        first = session_state(f, sid.value)
        again = f["C_Login"](sid.value, user, None, 0)
        as_so = f["C_Login"](sid.value, 0, None, 0)
        as_context = f["C_Login"](sid.value, 2, None, 0)
        logout = f["C_Logout"](sid.value)
        after = session_state(f, sid.value)
        print(
            f"  {label} after login({user_name}) {first}"
            f" relogin -> {again:#x} login(SO) -> {as_so:#x} login(CTX) -> {as_context:#x}"
            f" logout -> {logout:#x} now {after}"
        )
    f["C_CloseAllSessions"](1)
    sid = CK_ULONG()
    f["C_OpenSession"](1, 4, None, None, ctypes.byref(sid))
    print(
        "  RO public: login(CTX) ->",
        hex(f["C_Login"](sid.value, 2, None, 0)),
        "logout ->",
        hex(f["C_Logout"](sid.value)),
        session_state(f, sid.value),
    )


def main(path: str) -> None:
    f = bind(path)
    print(f"module: {path}")
    print("C_Initialize:", hex(f["C_Initialize"](None)))

    info = Info()
    print("C_GetInfo:", hex(f["C_GetInfo"](ctypes.byref(info))))
    print(
        f"  cryptoki={info.cryptokiVersion.major}.{info.cryptokiVersion.minor}"
        f" mfr={info.manufacturerID!r} desc={info.libraryDescription!r}"
        f" lib={info.libraryVersion.major}.{info.libraryVersion.minor} flags={info.flags:#x}"
    )

    count = CK_ULONG(0)
    print(
        "C_GetSlotList(count):",
        hex(f["C_GetSlotList"](0, None, ctypes.byref(count))),
        "n=",
        count.value,
    )
    slots = (CK_ULONG * count.value)()
    f["C_GetSlotList"](0, slots, ctypes.byref(count))
    print("  slots:", list(slots))

    for slot in slots:
        slot_info = SlotInfo()
        code = f["C_GetSlotInfo"](slot, ctypes.byref(slot_info))
        print(
            f"  C_GetSlotInfo({slot}): {code:#x} desc={slot_info.slotDescription!r}"
            f" mfr={slot_info.manufacturerID!r} flags={slot_info.flags:#x}"
            f" hw={slot_info.hardwareVersion.major}.{slot_info.hardwareVersion.minor}"
            f" fw={slot_info.firmwareVersion.major}.{slot_info.firmwareVersion.minor}"
        )
        print(f"    raw slotDescription {raw_field(slot_info, 'slotDescription', 64)}")
        print(f"    raw manufacturerID  {raw_field(slot_info, 'manufacturerID', 32)}")
        token = TokenInfo()
        code = f["C_GetTokenInfo"](slot, ctypes.byref(token))
        print(
            f"  C_GetTokenInfo({slot}): {code:#x} flags={token.flags:#x}"
            f" label={token.label!r} mfr={token.manufacturerID!r} model={token.model!r}"
            f" serial={token.serialNumber!r} utc={token.utcTime!r}"
        )
        for field, size in (
            ("label", 32),
            ("manufacturerID", 32),
            ("model", 16),
            ("serialNumber", 16),
            ("utcTime", 16),
        ):
            print(f"    raw {field:<16} {raw_field(token, field, size)}")
        print(
            f"    sessions max={token.ulMaxSessionCount:#x} now={token.ulSessionCount}"
            f" / maxRw={token.ulMaxRwSessionCount:#x} rw={token.ulRwSessionCount}"
            f" pinMin={token.ulMinPinLen} pinMax={token.ulMaxPinLen:#x}"
            f" pubMem={token.ulTotalPublicMemory:#x}/{token.ulFreePublicMemory:#x}"
            f" privMem={token.ulTotalPrivateMemory:#x}/{token.ulFreePrivateMemory:#x}"
        )
        mechanisms = CK_ULONG(0)
        code = f["C_GetMechanismList"](slot, None, ctypes.byref(mechanisms))
        listing = (CK_ULONG * mechanisms.value)()
        f["C_GetMechanismList"](slot, listing, ctypes.byref(mechanisms))
        print(f"    mechanisms: {code:#x} {[hex(m) for m in listing]}")
        for probe in MECHANISM_PROBES:
            buffer = (ctypes.c_ubyte * 24)()
            code = f["C_GetMechanismInfo"](slot, probe, ctypes.cast(buffer, ctypes.c_void_p))
            values = [int.from_bytes(bytes(buffer[i * 8 : i * 8 + 8]), "little") for i in range(3)]
            print(f"      mechInfo {probe:#x}: {code:#x} {[hex(v) for v in values]}")

    sessions_section(f)
    find_templates_section(f, discover_certificate_id())

    session = CK_ULONG()
    code = f["C_OpenSession"](1, 4, None, None, ctypes.byref(session))
    print("C_OpenSession:", hex(code), "h=", session.value)
    print("C_Login:", hex(f["C_Login"](session.value, 1, None, 0)))

    for class_id, label in CLASSES:
        code, handles = find(f, session.value, class_id)
        print(f"  find {label:<20} rc={code:#x} {handles}")
        for handle in handles:
            for attribute_type in sorted(ATTRIBUTE_NAMES):
                print(
                    f"      obj {handle} {ATTRIBUTE_NAMES[attribute_type]:<26}"
                    f" {describe_attribute(f, session.value, handle, attribute_type)}"
                )


if __name__ == "__main__":
    main(sys.argv[1])

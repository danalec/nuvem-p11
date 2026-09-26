"""Guards the riskiest part of the binding: the C layouts that only exist in Python.

The 68-entry ``CK_FUNCTION_LIST`` and the three info structs are declared by hand in
``nuvem_p11.p11``. If any of them drifted from the spec, the browser would call the wrong
function or read the wrong bytes, so this compiles a probe against p11-kit's ``pkcs11.h``
and diffs every offset.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys

import pytest

from nuvem_p11.p11.cabi import FUNCTION_LIST_SIZE, FUNCTION_NAMES, SIGNATURES, FunctionList
from nuvem_p11.p11.constants import ADVERTISED_MECHANISMS, CRYPTOKI_VERSION
from tools.dump_module import Info, SlotInfo, TokenInfo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC = shutil.which("cc") or shutil.which("gcc")

INFO_STRUCTS = {"CK_INFO": Info, "CK_SLOT_INFO": SlotInfo, "CK_TOKEN_INFO": TokenInfo}


def _p11_kit_include() -> str | None:
    try:
        flags = subprocess.run(
            ["pkg-config", "--cflags", "p11-kit-1"], check=True, capture_output=True, text=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        flags = "-I/usr/include/p11-kit-1"
    include = flags.split("-I")[-1] if "-I" in flags else None
    return include if include and os.path.isdir(include) else None


def test_table_has_exactly_68_entries():
    assert len(SIGNATURES) == 68
    assert len(FUNCTION_NAMES) == len(set(FUNCTION_NAMES)) == 68


def test_function_list_layout():
    # CK_VERSION is two bytes, then 6 bytes of padding before the first pointer.
    assert FUNCTION_LIST_SIZE == 8 + 68 * ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(FunctionList) == FUNCTION_LIST_SIZE
    assert FunctionList.C_Initialize.offset == 8
    assert FunctionList.C_GetFunctionList.offset == 32
    assert FunctionList.C_Sign.offset == 352
    assert FunctionList.C_WaitForSlotEvent.offset == 544


def test_info_struct_layouts():
    assert ctypes.sizeof(Info) == 88
    assert Info.flags.offset == 40
    assert Info.libraryDescription.offset == 48
    assert Info.libraryVersion.offset == 80

    assert ctypes.sizeof(SlotInfo) == 112
    assert SlotInfo.manufacturerID.offset == 64
    assert SlotInfo.flags.offset == 96
    assert SlotInfo.hardwareVersion.offset == 104
    assert SlotInfo.firmwareVersion.offset == 106

    assert ctypes.sizeof(TokenInfo) == 208
    assert TokenInfo.model.offset == 64
    assert TokenInfo.serialNumber.offset == 80
    assert TokenInfo.flags.offset == 96
    assert TokenInfo.ulMaxSessionCount.offset == 104
    assert TokenInfo.ulMinPinLen.offset == 144
    assert TokenInfo.hardwareVersion.offset == 184
    assert TokenInfo.utcTime.offset == 188


@pytest.mark.skipif(CC is None, reason="a C compiler is required")
def test_every_offset_matches_the_real_headers(tmp_path):
    include = _p11_kit_include()
    if include is None:
        pytest.skip("p11-kit headers not installed")

    probe = tmp_path / "probe.c"
    probe.write_text(
        subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "emit_abi_probe.py")],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    binary = tmp_path / "probe"
    subprocess.run([CC, "-o", str(binary), str(probe), f"-I{include}"], check=True, capture_output=True)
    output = subprocess.run([str(binary)], check=True, capture_output=True, text=True).stdout

    sizes: dict[str, int] = {}
    offsets: dict[str, int] = {}
    for line in output.splitlines():
        name, _, value = line.partition(" ")
        if name == "sizeof":
            struct, _, struct_size = value.partition(" ")
            sizes[struct] = int(struct_size)
        else:
            offsets[name] = int(value)

    assert sizes["CK_FUNCTION_LIST"] == ctypes.sizeof(FunctionList)
    assert sizes["CK_INFO"] == ctypes.sizeof(Info)
    assert sizes["CK_SLOT_INFO"] == ctypes.sizeof(SlotInfo)
    assert sizes["CK_TOKEN_INFO"] == ctypes.sizeof(TokenInfo)

    expected: dict[str, int] = {}
    for name in FUNCTION_NAMES:
        expected[name] = getattr(FunctionList, name).offset
    for struct, cls in INFO_STRUCTS.items():
        for field, _ in cls._fields_:
            expected[f"{struct}.{field}"] = getattr(cls, field).offset

    mismatches = {
        name: (expected[name], offsets.get(name))
        for name in expected
        if offsets.get(name) != expected[name]
    }
    assert not mismatches, f"offsets differ (python, C): {mismatches}"
    assert len(offsets) == len(expected)


def test_cryptoki_version_is_the_one_the_module_reports():
    # The original writes {2,20} into CK_INFO despite implementing the v2.40 API surface.
    assert CRYPTOKI_VERSION == (2, 20)
    assert ADVERTISED_MECHANISMS == (0x1, 0xD)

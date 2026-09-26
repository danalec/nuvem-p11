"""Loads the built native shim the way a PKCS#11 loader does.

Skipped unless ``make`` has produced ``shim/libnuvemp11.so``. Only machine-independent
identity is asserted here -- object enumeration depends on the certificates installed on the
machine, and is covered by :mod:`tests.test_p11_module` with a synthetic certificate.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import shutil
import subprocess

import pytest

from nuvem_p11.errors import CKR_ARGUMENTS_BAD
from nuvem_p11.p11 import constants as k
from nuvem_p11.p11.cabi import callables_at

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIM = os.path.join(ROOT, "shim", "libnuvemp11.so")
CC = shutil.which("cc") or shutil.which("gcc")

pytestmark = pytest.mark.skipif(
    not os.path.exists(SHIM), reason="run `make` to build the native shim"
)


@pytest.fixture(scope="module")
def functions():
    # The official module (and therefore our shim, built the same way) relies on the host for
    # libc; a plain Python process needs libgcc_s promoted for the official one only.
    ctypes.CDLL(ctypes.util.find_library("gcc_s") or "libgcc_s.so.1", mode=ctypes.RTLD_GLOBAL)
    library = ctypes.CDLL(SHIM)

    get_list = library.C_GetFunctionList
    get_list.restype = ctypes.c_ulong
    get_list.argtypes = [ctypes.POINTER(ctypes.c_void_p)]

    # A NULL pointer argument is an error, matching the original.
    assert get_list(None) == CKR_ARGUMENTS_BAD

    table = ctypes.c_void_p()
    assert get_list(ctypes.byref(table)) == 0
    assert table.value
    return callables_at(table.value)


def test_shim_exports_a_complete_function_list(functions):
    assert len(functions) == 68
    assert all(callable(entry) for entry in functions.values())


#: A loader with no Python in the process: it drops the shim in, does what a browser does.
LOADER_SOURCE = r"""
#include <dlfcn.h>
#include <stdio.h>

/*
 * CK_FUNCTION_LIST opens with CK_VERSION (two bytes plus six of padding) and then the
 * pointers, so C_Initialize is at offset 8 -- the layout tests/test_p11_abi.py pins.
 */
typedef int (*ck_rv_fn)(void *);

int main(int argc, char **argv)
{
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    void *list = NULL;
    int (*get_list)(void **);
    ck_rv_fn initialize;

    if (library == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 2;
    }
    get_list = dlsym(library, "C_GetFunctionList");
    if (get_list == NULL) {
        fprintf(stderr, "no C_GetFunctionList\n");
        return 3;
    }
    /* Building the list is where the shim starts CPython and imports our package. */
    if (get_list(&list) != 0 || list == NULL) {
        fprintf(stderr, "C_GetFunctionList failed\n");
        return 4;
    }
    initialize = *(ck_rv_fn *)((char *)list + 8);
    if (initialize(NULL) != 0) {
        fprintf(stderr, "C_Initialize failed\n");
        return 5;
    }
    printf("ok\n");
    return 0;
}
"""


@pytest.mark.skipif(CC is None, reason="a C compiler is required")
def test_shim_loads_from_a_process_without_python(tmp_path):
    """The shim must reach its own package with no Python host to help it.

    This is the browser case: NSS drops the shim into Firefox, which knows nothing about
    Python, so ``bootstrap`` initialises CPython itself and puts the compiled-in
    ``-DNUVEM_P11_PYTHONPATH`` on ``sys.path``. Every other test in this file loads the shim
    from *this* Python process, where the package is already importable -- so a missing
    ``-D`` would go unnoticed here and only show up as a module that loads and then fails
    inside the browser.
    """
    source = tmp_path / "loader.c"
    source.write_text(LOADER_SOURCE)
    binary = tmp_path / "loader"
    subprocess.run([CC, "-o", str(binary), str(source), "-ldl"], check=True)

    # An embedded interpreter puts the working directory on ``sys.path``, and the shim
    # prefers ``$NUVEM_P11_PYTHONPATH`` to the compiled-in value -- either one would let
    # this pass without the ``-D``.
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "NUVEM_P11_PYTHONPATH")
    }
    result = subprocess.run(
        [str(binary), SHIM], cwd=tmp_path, env=environment, capture_output=True, text=True
    )
    assert result.returncode == 0, f"loader exit {result.returncode}: {result.stderr}"
    assert result.stdout.strip() == "ok"


def test_shim_reports_the_token_identity(functions):
    from tools.dump_module import Info, SlotInfo, TokenInfo

    assert functions["C_Initialize"](None) == 0

    info = Info()
    assert functions["C_GetInfo"](ctypes.byref(info)) == 0
    assert info.manufacturerID == b"SERPRO"
    assert info.libraryDescription == b"Modulo PKCS#11 SERPRO SerproID"

    count = ctypes.c_ulong(0)
    assert functions["C_GetSlotList"](0, None, ctypes.byref(count)) == 0
    assert count.value == 1

    slot_info = SlotInfo()
    assert functions["C_GetSlotInfo"](k.SLOT_ID, ctypes.byref(slot_info)) == 0
    assert slot_info.slotDescription == b"Slot SerproID"
    assert slot_info.flags == 0x7

    token = TokenInfo()
    assert functions["C_GetTokenInfo"](k.SLOT_ID, ctypes.byref(token)) == 0
    assert token.label == b"SerproID"
    assert token.flags == 0x50A

    mechanisms = ctypes.c_ulong(0)
    assert functions["C_GetMechanismList"](k.SLOT_ID, None, ctypes.byref(mechanisms)) == 0
    listing = (ctypes.c_ulong * mechanisms.value)()
    functions["C_GetMechanismList"](k.SLOT_ID, listing, ctypes.byref(mechanisms))
    assert list(listing) == [k.CKM_RSA_PKCS, k.CKM_RSA_PKCS_PSS]
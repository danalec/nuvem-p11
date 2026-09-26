"""Generate a C probe that prints the layouts the Python side assumes.

Compiled against p11-kit's ``pkcs11.h`` (the same spec NSS uses) and compared with the
offsets ctypes computes. That comparison is what makes a 68-entry function table and three
hand-declared info structs safe to keep in Python.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nuvem_p11.p11.cabi import FUNCTION_NAMES  # noqa: E402

INFO_STRUCTS = {
    "CK_INFO": ("cryptokiVersion", "manufacturerID", "flags", "libraryDescription", "libraryVersion"),
    "CK_SLOT_INFO": (
        "slotDescription",
        "manufacturerID",
        "flags",
        "hardwareVersion",
        "firmwareVersion",
    ),
    "CK_TOKEN_INFO": (
        "label",
        "manufacturerID",
        "model",
        "serialNumber",
        "flags",
        "ulMaxSessionCount",
        "ulSessionCount",
        "ulMaxRwSessionCount",
        "ulRwSessionCount",
        "ulMaxPinLen",
        "ulMinPinLen",
        "ulTotalPublicMemory",
        "ulFreePublicMemory",
        "ulTotalPrivateMemory",
        "ulFreePrivateMemory",
        "hardwareVersion",
        "firmwareVersion",
        "utcTime",
    ),
}


def main() -> None:
    lines = [
        "#include <stddef.h>",
        "#include <stdio.h>",
        "#include <p11-kit/pkcs11.h>",
        "int main(void) {",
        '    printf("sizeof CK_FUNCTION_LIST %zu\\n", sizeof(CK_FUNCTION_LIST));',
    ]
    for name in FUNCTION_NAMES:
        lines.append(f'    printf("{name} %zu\\n", offsetof(CK_FUNCTION_LIST, {name}));')
    for struct, fields in INFO_STRUCTS.items():
        lines.append(f'    printf("sizeof {struct} %zu\\n", sizeof({struct}));')
        for field in fields:
            lines.append(f'    printf("{struct}.{field} %zu\\n", offsetof({struct}, {field}));')
    lines += ["    return 0;", "}"]
    print("\n".join(lines))


if __name__ == "__main__":
    main()

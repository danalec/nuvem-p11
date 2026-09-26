/*
 * serproidp11.so -- native shim that makes the Python implementation loadable by NSS.
 *
 * This file deliberately contains no PKCS#11 logic. It embeds CPython, asks
 * `nuvem_p11.p11.cabi` for the address of each of the 68 callbacks, and fills a real
 * `CK_FUNCTION_LIST`. Two things keep it honest:
 *
 *   - `generated_functions.h` is emitted from `nuvem_p11/p11/cabi.py`, so the assignment
 *     list cannot drift from the Python side;
 *   - the struct comes from p11-kit's `pkcs11.h`, so the compiler checks every member
 *     name and its exact function-pointer type.
 *
 * The GIL is released before returning to the caller: `C_GetFunctionList` is typically
 * called from a thread that goes back into C, and every later call arrives through a
 * ctypes callback, which acquires the GIL by itself.
 *
 * Build: see the Makefile (needs python3-config --includes and p11-kit headers).
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <p11-kit/pkcs11.h>

#include "generated_functions.h"

#ifndef NUVEM_P11_PYTHONPATH
#define NUVEM_P11_PYTHONPATH ""
#endif
#ifndef NUVEM_P11_PYTHON_SONAME
#define NUVEM_P11_PYTHON_SONAME ""
#endif
#ifndef NUVEM_P11_PYTHON_LIBNAME
#define NUVEM_P11_PYTHON_LIBNAME ""
#endif

/*
 * A PKCS#11 loader may dlopen us with RTLD_LOCAL. libpython then lands in a local scope,
 * and the extension modules CPython dlopens afterwards (``_struct``, ``_json``, ...) fail to
 * resolve its symbols. Re-opening it with RTLD_GLOBAL promotes it into the global scope.
 * Harmless when the host is already a Python process.
 */
static void promote_libpython(void)
{
    static const char *candidates[] = {NUVEM_P11_PYTHON_SONAME, NUVEM_P11_PYTHON_LIBNAME};
    size_t index;

    for (index = 0; index < sizeof(candidates) / sizeof(candidates[0]); ++index) {
        if (candidates[index] == NULL || *candidates[index] == '\0')
            continue;
        if (dlopen(candidates[index], RTLD_NOW | RTLD_GLOBAL) != NULL)
            return;
    }
}

static CK_FUNCTION_LIST g_function_list;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static int g_failed = 0;

/*
 * Set when *we* are the ones who started the interpreter (Firefox, i.e. a host that knows
 * nothing about CPython). In that case the GIL has to be dropped before returning to the
 * caller, because the calling thread goes back into C and every later PKCS#11 call arrives
 * through a ctypes callback that acquires the GIL itself.
 *
 * When Python was already running (a Python host loading the shim), ctypes around the
 * foreign call owns the GIL and touching it here would corrupt the thread state.
 */
static int g_owns_interpreter = 0;

static void add_python_path(void)
{
    const char *extra = getenv("NUVEM_P11_PYTHONPATH");
    PyObject *sys_path;
    PyObject *item;

    if (extra == NULL || *extra == '\0')
        extra = NUVEM_P11_PYTHONPATH;
    if (extra == NULL || *extra == '\0')
        return;
    if (!Py_IsInitialized())
        return;

    sys_path = PySys_GetObject("path"); /* borrowed */
    item = PyUnicode_FromString(extra);
    if (sys_path != NULL && item != NULL)
        PyList_Append(sys_path, item);
    Py_XDECREF(item);
}

static void bootstrap(void)
{
    PyObject *cabi;
    PyObject *symbols;
    PyGILState_STATE gil;
    int missing = 0;

    if (!Py_IsInitialized()) {
        promote_libpython();
        /* No signal handlers: we are a guest inside a browser process. */
        Py_InitializeEx(0);
        add_python_path();
        g_owns_interpreter = 1;
    }

    /*
     * A Python host reaches us through ctypes, which releases the GIL around the foreign
     * call, so the interpreter must be entered explicitly before touching its API. When we
     * are the ones who initialised it the GIL is already held and this is a no-op.
     */
    gil = PyGILState_Ensure();

    cabi = PyImport_ImportModule("nuvem_p11.p11.cabi");
    if (cabi == NULL) {
        PyErr_Print();
        PyGILState_Release(gil);
        g_failed = 1;
        return;
    }
    symbols = PyObject_CallMethod(cabi, "function_symbols", NULL);
    if (symbols == NULL) {
        PyErr_Print();
        Py_DECREF(cabi);
        PyGILState_Release(gil);
        g_failed = 1;
        return;
    }
    if (!PyDict_Check(symbols)) {
        fprintf(stderr, "serproidp11: function_symbols() did not return a dict\n");
        Py_DECREF(symbols);
        Py_DECREF(cabi);
        PyGILState_Release(gil);
        g_failed = 1;
        return;
    }

    g_function_list.version.major = (CK_BYTE)2;
    g_function_list.version.minor = (CK_BYTE)20;

#define NUVEM_P11_ASSIGN(name)                                                             \
    do {                                                                                  \
        PyObject *value = PyDict_GetItemString(symbols, #name); /* borrowed */             \
        if (value != NULL)                                                                 \
            g_function_list.name =                                                        \
                (__typeof__(g_function_list.name))(uintptr_t)PyLong_AsUnsignedLongLong(value); \
        else                                                                               \
            missing++;                                                                     \
    } while (0);

    NUVEM_P11_FUNCTIONS(NUVEM_P11_ASSIGN)
#undef NUVEM_P11_ASSIGN

    Py_DECREF(symbols);
    Py_DECREF(cabi);
    PyGILState_Release(gil);

    if (missing != 0) {
        g_failed = 1;
        return;
    }
    if (g_owns_interpreter) {
        /*
         * We started the interpreter, so the GIL is ours and the calling thread is about to
         * return to C (NSS keeps the table and never calls back into us on this thread).
         * Hand it back so the ctypes callbacks can take it from any thread.
         */
        (void)PyEval_SaveThread();
        g_owns_interpreter = 0;
    }
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    pthread_once(&g_once, bootstrap);
    if (g_failed)
        return CKR_GENERAL_ERROR;
    *ppFunctionList = &g_function_list;
    return CKR_OK;
}

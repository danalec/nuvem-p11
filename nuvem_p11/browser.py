"""Browser integration: the PKCS#11 module and the ICP-Brasil roots, as the official helper does it.

Reverted from the official desktop helper (``smartcert/util/so/SO.java`` and ``Unix.java``):

* Firefox -- every profile in ``~/.mozilla/firefox/profiles.ini`` gets a two-line block
  (``library=``/``name=SerproID``) **appended** to its ``pkcs11.txt``, unless the file already
  mentions ``SerproID`` or its predecessor ``NeoID``.
* Chromium/others -- ``modutil -force -add`` against ``~/.pki/nssdb`` (the profile *and* the
  shared NSS database are both NSS consumers, hence the two front ends).
* Certificates -- the five ICP-Brasil roots are installed with ``certutil -A`` into every NSS
  database that exists, Firefox profiles (legacy ``cert8.db`` or ``cert9.db``) and ``~/.pki/nssdb``.

Nothing here reads ``$HOME`` on its own: ``home`` is a parameter, as is the subprocess
``runner``, so the exact command lines can be asserted without ``modutil``/``certutil``
installed and without touching the caller's real profiles.
"""

from __future__ import annotations

import configparser
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable

#: The name our own module is built and installed as.
MODULE_BASENAME = "libnuvemp11.so"

#: Where a system-wide install would put it.
SYSTEM_LIB = os.path.join("/usr/lib", MODULE_BASENAME)


def default_lib() -> str | None:
    """Where our module is: ``$NUVEM_P11_LIB``, then ``/usr/lib``, then a source checkout.

    ``None`` when none of them exists. It deliberately has **no** fallback to
    ``/usr/lib/libserproidp11.so`` -- that is what the official helper registers, and
    pointing the browser at Serpro's implementation instead of this one is the single thing
    this tool must never do by accident.
    """
    candidates = (
        os.environ.get("NUVEM_P11_LIB"),
        SYSTEM_LIB,
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "shim",
            MODULE_BASENAME,
        ),
    )
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None

MODULE_NAME = "SerproID"
#: Name the previous generation of the token used; a profile carrying it needs no change.
LEGACY_MODULE_NAME = "NeoID"

FIREFOX_DIR = os.path.join(".mozilla", "firefox")
PROFILES_INI = os.path.join(FIREFOX_DIR, "profiles.ini")
PKCS11_FILE = "pkcs11.txt"
NSSDB = os.path.join(".pki", "nssdb")

#: Bundled roots, in the order the original installs them.
AC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ac")

#: ``(filename, -n argument)`` -- the name is the one the original passes to ``certutil``.
AC_CERTS: tuple[tuple[str, str], ...] = (
    ("ICP-Brasil.crt", "Autoridade Certificadora Raiz Brasileira v1"),
    ("ICP-Brasilv2.crt", "Autoridade Certificadora Raiz Brasileira v2"),
    ("ICP-Brasilv5.crt", "Autoridade Certificadora Raiz Brasileira v5"),
    ("acserprov4.crt", "Autoridade Certificadora SERPRO v4"),
    ("acserproacfv5.crt", "Autoridade Certificadora do SERPRO Final v5"),
)

#: Line separator of the platform, as the Java helper uses ``System.lineSeparator()``.
LS = os.linesep

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]
LogFn = Callable[[str], None]


def subprocess_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Default runner: run ``modutil``/``certutil`` and hand back the completed process.

    ``stdin`` is closed on purpose: ``modutil`` stops to warn about a running browser and asks
    for confirmation, which would otherwise consume the caller's input -- or hang when there is
    none. With no stdin the prompt reads end-of-file and the command goes ahead.
    """
    return subprocess.run(
        argv, capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL
    )


def _noop(message: str) -> None:
    """Default log sink; the library never writes anywhere on its own."""
    return None


def _run(runner: Runner, argv: list[str], log: LogFn) -> subprocess.CompletedProcess[str] | None:
    """Run one command; a missing binary is a logged failure, never an exception."""
    log(" ".join(argv))
    try:
        return runner(argv)
    except OSError as exc:
        log(f"error: {argv[0]}: {exc}")
        return None


def _output(proc: subprocess.CompletedProcess[str] | None) -> str:
    if proc is None:
        return ""
    return (proc.stdout or "") + (proc.stderr or "")


def firefox_profiles(home: str) -> list[str]:
    """Profile directories listed in ``<home>/.mozilla/firefox/profiles.ini``.

    Sections whose name does not start with ``Profile`` are ignored, and ``Path`` is resolved
    against the Firefox directory only when ``IsRelative=1``. A missing or unreadable
    ``profiles.ini`` yields no profiles.
    """
    firefox_dir = os.path.join(home, FIREFOX_DIR)
    ini = os.path.join(home, PROFILES_INI)
    parser = configparser.RawConfigParser(strict=False)
    try:
        with open(ini, encoding="utf-8", errors="replace") as handle:
            parser.read_file(handle)
    except (OSError, configparser.Error):
        return []

    profiles: list[str] = []
    for section in parser.sections():
        if not section.startswith("Profile"):
            continue
        path = parser.get(section, "Path", fallback="").strip()
        if not path:
            continue
        if parser.get(section, "IsRelative", fallback="0").strip() == "1":
            profiles.append(os.path.join(firefox_dir, path))
        else:
            profiles.append(path)
    return profiles


@dataclass(frozen=True)
class SetupResult:
    """Outcome of one configuration step.

    ``firefox``/``chrome`` are tri-state: ``True`` when the module is registered, ``False``
    when a command failed, ``None`` when there was nothing to do (no Firefox profiles, no NSS
    database). ``details`` records what happened, per front end.
    """

    firefox: bool | None
    chrome: bool | None
    details: dict = field(default_factory=dict)


# --- Firefox ---------------------------------------------------------------------------


def _read(path: str) -> str:
    # newline="" and surrogateescape: the file is rewritten verbatim, byte for byte.
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as handle:
        return handle.read()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as handle:
        handle.write(text)


def _module_block(lib: str) -> str:
    return f"library={lib}{LS}name={MODULE_NAME}{LS}{LS}"


#: Any line equal to one of these means the module is registered in a ``pkcs11.txt``.
_CONFIGURED_NAMES = frozenset(
    line.lower() for line in (f"name={MODULE_NAME}", f"name={LEGACY_MODULE_NAME}")
)


def _registration(text: str) -> tuple[int, str | None, str | None]:
    """The module's registration: ``(line index, library path or None, name or None)``.

    ``pkcs11.txt`` pairs a ``library=`` line with the ``name=`` line under it, so the path is
    the line before the name. Looking only for the name -- which is all the official helper
    needs, since it is the only thing that writes the file -- is not enough here: a profile
    registered by the official desktop points at ``/usr/lib/libserproidp11.so``, and switching
    implementations would leave the browser loading a module that no longer exists, with the
    certificate silently missing from every handshake.

    The name comes back too because the legacy ``NeoID`` is a *different* module: it may
    belong to the previous generation of the product, and hijacking its path would be wrong.
    """
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.lower() not in _CONFIGURED_NAMES:
            continue
        name = stripped.split("=", 1)[1]
        if index > 0 and lines[index - 1].strip().startswith("library="):
            return index - 1, lines[index - 1].strip()[len("library=") :], name
        return index, None, name
    return -1, None, None


def _mentions_module(text: str) -> bool:
    return _registration(text)[0] >= 0


def _strip_module_block(text: str, lib: str) -> str | None:
    """Remove the two block lines plus the blank line appended after them, or None."""
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip() != f"library={lib}":
            continue
        if index + 1 >= len(lines) or lines[index + 1].strip() != f"name={MODULE_NAME}":
            continue
        end = index + 2
        if end < len(lines) and not lines[end].strip():
            end += 1
        return "".join(lines[:index] + lines[end:])
    return None


def _configure_firefox(home: str, lib: str, log: LogFn, details: dict) -> bool | None:
    profiles = firefox_profiles(home)
    targets = [profile for profile in profiles if os.path.isdir(profile)]
    details["profiles"] = profiles
    details["missing"] = [profile for profile in profiles if profile not in targets]
    if not targets:
        details["firefox"] = "absent"
        return None

    changed: list[str] = []
    updated: list[str] = []
    already: list[str] = []
    failed: list[str] = []
    for profile in targets:
        path = os.path.join(profile, PKCS11_FILE)
        try:
            text = _read(path)
        except FileNotFoundError:
            text = ""  # the original creates the file empty before looking at it
        except OSError as exc:
            log(f"error: {path}: {exc}")
            failed.append(profile)
            continue
        index, registered, name = _registration(text)
        if index >= 0 and (registered == lib or name != MODULE_NAME):
            # Either already pointing at us, or the legacy module's own registration, which is
            # not ours to rewrite.
            already.append(profile)
            continue
        if index >= 0:
            # Registered under our name, but pointing at some other module -- the official
            # one, typically, or a build of ours from a different path. Rewrite that line.
            lines = text.splitlines(keepends=True)
            lines[index] = f"library={lib}{LS}"
            try:
                _write(path, "".join(lines))
            except OSError as exc:
                log(f"error: {path}: {exc}")
                failed.append(profile)
                continue
            log(f"perfil {profile}: biblioteca trocada de {registered!r} para {lib!r}")
            updated.append(profile)
            continue
        # The original appends blindly; a missing separator would merge our block into the
        # previous line, so add one when the file does not end with a newline.
        separator = "" if not text or text.endswith(LS) else LS
        try:
            _write(path, text + separator + _module_block(lib))
        except OSError as exc:
            log(f"error: {path}: {exc}")
            failed.append(profile)
            continue
        changed.append(profile)

    details["changed"] = changed
    details["updated"] = updated
    details["present"] = already
    details["firefox"] = "failed" if failed else ("configured" if changed or updated else "already")
    return not failed


def _remove_firefox(home: str, lib: str, log: LogFn, details: dict) -> bool | None:
    profiles = [profile for profile in firefox_profiles(home) if os.path.isdir(profile)]
    details["profiles"] = profiles
    if not profiles:
        details["firefox"] = "absent"
        return None

    removed: list[str] = []
    failed: list[str] = []
    for profile in profiles:
        path = os.path.join(profile, PKCS11_FILE)
        try:
            text = _read(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            log(f"error: {path}: {exc}")
            failed.append(profile)
            continue
        stripped = _strip_module_block(text, lib)
        if stripped is None:
            continue
        try:
            # An empty pkcs11.txt is litter: the file only existed for our block.
            if stripped:
                _write(path, stripped)
            else:
                os.remove(path)
        except OSError as exc:
            log(f"error: {path}: {exc}")
            failed.append(profile)
            continue
        removed.append(profile)

    details["removed"] = removed
    details["firefox"] = "failed" if failed else ("removed" if removed else "absent")
    return not failed


# --- NSS database (Chromium and friends) ------------------------------------------------


def _nssdb(home: str) -> str:
    return os.path.join(home, NSSDB)


def _dbdir(path: str) -> str:
    return f"sql:{path}"


def _registered_chrome_library(listing: str) -> str | None:
    """The ``library name:`` of the SerproID entry in ``modutil -list`` output, if any.

    The listing numbers each module and prints its path on a following line, so the path has
    to be tied to the entry carrying the name -- the same reason the Firefox side reads the
    path and not only the name.
    """
    entry: str | None = None
    for line in listing.splitlines():
        stripped = line.strip()
        header = re.match(r"\d+\.\s+(.+)$", stripped)
        if header is not None:
            entry = header.group(1).strip()
            continue
        if stripped.lower().startswith("library name:") and entry in (
            MODULE_NAME,
            LEGACY_MODULE_NAME,
        ):
            return stripped.split(":", 1)[1].strip()
    return None


def _configure_chrome(home: str, lib: str, runner: Runner, log: LogFn, details: dict) -> bool | None:
    nssdb = _nssdb(home)
    details["nssdb"] = nssdb if os.path.isdir(nssdb) else None
    if not os.path.isdir(nssdb):
        log("Diretório de configurações da NSS não foi encontrado")
        details["chrome"] = "absent"
        return None

    dbdir = _dbdir(nssdb)
    listing = _output(_run(runner, ["modutil", "-list", "-dbdir", dbdir], log))
    registered = _registered_chrome_library(listing)
    if registered == lib:
        details["chrome"] = "present"
        return True
    if registered is None and (MODULE_NAME in listing or LEGACY_MODULE_NAME in listing):
        # The name is there but the path could not be read: leave it alone rather than clobber
        # a registration we do not understand.
        log(f"{MODULE_NAME} consta na listagem, mas sem caminho legível; deixando como está")
        details["chrome"] = "present"
        return True

    # ``-force -add`` is what the original passes, but it refuses to replace an entry whose
    # library cannot be loaded -- exactly the case of a registration left behind by the
    # official package. Turning the entry over first, then adding ours, does work.
    if registered is not None:
        _run(runner, ["modutil", "-delete", MODULE_NAME, "-dbdir", dbdir], log)
    proc = _run(
        runner,
        ["modutil", "-force", "-add", MODULE_NAME, "-dbdir", dbdir, "-libfile", lib],
        log,
    )
    if proc is None or proc.returncode != 0:
        details["chrome"] = "failed"
        return False
    if registered is not None:
        log(f"nssdb: biblioteca trocada de {registered!r} para {lib!r}")
    details["chrome"] = "updated" if registered is not None else "added"
    return True


def _remove_chrome(home: str, runner: Runner, log: LogFn, details: dict) -> bool | None:
    nssdb = _nssdb(home)
    details["nssdb"] = nssdb if os.path.isdir(nssdb) else None
    if not os.path.isdir(nssdb):
        details["chrome"] = "absent"
        return None

    dbdir = _dbdir(nssdb)
    listing = _output(_run(runner, ["modutil", "-list", "-dbdir", dbdir], log))
    if MODULE_NAME not in listing and LEGACY_MODULE_NAME not in listing:
        details["chrome"] = "absent"
        return True

    proc = _run(runner, ["modutil", "-dbdir", dbdir, "-delete", MODULE_NAME], log)
    if proc is None or proc.returncode != 0:
        details["chrome"] = "failed"
        return False
    details["chrome"] = "deleted"
    return True


# --- Certificates -------------------------------------------------------------------------


def _cert_databases(home: str) -> list[str]:
    """Every NSS database the original installs certificates into, as ``-d`` arguments."""
    databases: list[str] = []
    for profile in firefox_profiles(home):
        if not os.path.isdir(profile):
            continue
        if os.path.exists(os.path.join(profile, "cert8.db")):
            databases.append(profile)
        if os.path.exists(os.path.join(profile, "cert9.db")):
            databases.append(_dbdir(profile))
    nssdb = _nssdb(home)
    if os.path.isdir(nssdb):
        databases.append(_dbdir(nssdb))
    return databases


def _install_into(
    databases: list[str],
    name: str,
    path: str,
    runner: Runner,
    log: LogFn,
) -> list[str]:
    installed: list[str] = []
    for database in databases:
        proc = _run(
            runner,
            ["certutil", "-A", "-n", name, "-d", database, "-t", "CT,C,C", "-i", path],
            log,
        )
        if proc is not None and proc.returncode == 0:
            installed.append(database)
    return installed


def install_ca_file(
    home: str,
    name: str,
    path: str,
    *,
    runner: Runner = subprocess_runner,
    log: LogFn | None = None,
) -> list[str]:
    """Install one certificate file as ``name`` into every NSS database of ``home``.

    Returns the databases the ``certutil -A`` call succeeded on -- empty when nothing was
    installed. Used both for the bundled roots and for the intermediate certificates of a
    server chain (arbitrary ``name``/``path``).
    """
    log = log or _noop
    return _install_into(_cert_databases(home), name, path, runner, log)


def install_cas(
    home: str,
    *,
    runner: Runner = subprocess_runner,
    log: LogFn | None = None,
) -> list[str]:
    """Install the five bundled ICP-Brasil roots; returns the names installed everywhere."""
    log = log or _noop
    databases = _cert_databases(home)
    if not databases:
        log("no NSS database found")
        return []

    installed: list[str] = []
    for filename, name in AC_CERTS:
        path = os.path.join(AC_DIR, filename)
        if not os.path.exists(path):
            log(f"error: {path}: certificado ausente")
            continue
        if len(_install_into(databases, name, path, runner, log)) == len(databases):
            installed.append(name)
    return installed


# --- Front ends ---------------------------------------------------------------------------


def configure(
    home: str,
    *,
    lib: str,
    runner: Runner = subprocess_runner,
    log: LogFn | None = None,
) -> SetupResult:
    """Register the module in Firefox (``pkcs11.txt``) and in the shared NSS database."""
    log = log or _noop
    details: dict = {}
    firefox = _configure_firefox(home, lib, log, details)
    chrome = _configure_chrome(home, lib, runner, log, details)
    return SetupResult(firefox=firefox, chrome=chrome, details=details)


def remove(
    home: str,
    *,
    lib: str,
    runner: Runner = subprocess_runner,
    log: LogFn | None = None,
) -> SetupResult:
    """Undo :func:`configure`: drop the block from every ``pkcs11.txt`` and delete the module.

    Idempotent -- a second run finds nothing to do. A ``pkcs11.txt`` left empty by the removal
    is deleted, so a profile that had no file before :func:`configure` has none afterwards; a
    file that did not end with a newline keeps the separator that was inserted.
    """
    log = log or _noop
    details: dict = {}
    firefox = _remove_firefox(home, lib, log, details)
    chrome = _remove_chrome(home, runner, log, details)
    return SetupResult(firefox=firefox, chrome=chrome, details=details)

"""Environment resolution, device identity and the log.

Mirrors ``$HOME/.config/serproid/`` handling of the official module:

* ``ambiente``      -- selects the backend host (0 dev, 1 homolog, 2 production, 3 test)
* ``maquinaId*``    -- the 40 hex char device identifier sent as ``X-SMARTCERT-UUID``
* ``serproid.log``  -- append-only log, ``%Y-%m-%d %H:%M:%S [2.1.6] <msg>\\n``
* ``atualizar``     -- marker written when the backend advertises an update
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from .errors import SerproIDError  # noqa: F401  (re-exported for callers)

CONFIG_SUBDIR = os.path.join(".config", "serproid")
CERTIFICATES_SUBDIR = "certificados"
LOG_NAME = "serproid.log"
UPDATE_NAME = "atualizar"

VERSION = "2.1.6"

AMBIENTE_DEV = 0
AMBIENTE_HOMOLOG = 1
AMBIENTE_PRODUCTION = 2
AMBIENTE_TEST = 3

#: Backend host per ``ambiente``. 0/3 are Serpro's internal "estaleiro" hosts.
HOSTS = {
    AMBIENTE_DEV: "desneoid.np.estaleiro.serpro.gov.br",
    AMBIENTE_HOMOLOG: "hom.serproid.serpro.gov.br",
    AMBIENTE_PRODUCTION: "serproid.serpro.gov.br",
    AMBIENTE_TEST: "tesneoid.np.estaleiro.serpro.gov.br",
}

#: Device-identifier file per ``ambiente``.
MACHINE_ID_FILES = {
    AMBIENTE_DEV: "maquinaIdDes",
    AMBIENTE_HOMOLOG: "maquinaIdHom",
    AMBIENTE_PRODUCTION: "maquinaId",
    AMBIENTE_TEST: "maquinaIdTes",
}

DEFAULT_PORT = "443"


def c_strtol(text: str, base: int = 10) -> int:
    """``strtol(3)`` semantics: leading whitespace, optional sign, digits, else 0.

    An *empty* ``ambiente`` file yields 0 (development), not the production default -- see
    :func:`read_ambiente`.
    """
    index = 0
    while index < len(text) and text[index] in " \t\n\r\v\f":
        index += 1
    sign = 1
    if index < len(text) and text[index] in "+-":
        if text[index] == "-":
            sign = -1
        index += 1
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"[:base]
    start = index
    while index < len(text) and text[index].lower() in digits:
        index += 1
    if index == start:
        return 0
    return sign * int(text[start:index], base)


def _first_line(path: str) -> str | None:
    """``getline`` equivalent: first ``\\n``-delimited line, or None if unreadable."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            line = handle.readline()
    except OSError:
        return None
    if line == "":
        return ""
    return line[:-1] if line.endswith("\n") else line


@dataclass(frozen=True)
class DeviceInfo:
    """Identity of the calling process, as reported to the backend."""

    executable: str
    pid: int

    @property
    def basename(self) -> str:
        return os.path.basename(self.executable)

    @classmethod
    def detect(cls) -> DeviceInfo:
        """Read ``/proc/self/exe`` like the original (full path logged, basename sent)."""
        try:
            executable = os.readlink("/proc/self/exe")
        except OSError:
            executable = ""
        return cls(executable=executable, pid=os.getpid())


class Log:
    """Append-only log in the original's exact format.

    The official module logs unconditionally and never creates the directory (a missing
    ``~/.config/serproid`` makes its ``fprintf`` dereference NULL). Here a missing
    directory is tolerated silently.
    """

    def __init__(self, directory: str, enabled: bool = True) -> None:
        self.path = os.path.join(directory, LOG_NAME)
        self.enabled = enabled

    def __call__(self, message: str) -> None:
        if not self.enabled:
            return
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        try:
            with open(self.path, "a+", encoding="utf-8") as handle:
                handle.write(f"{stamp} [{VERSION}] {message}\n")
        except OSError:
            pass


class Config:
    """Filesystem layout and per-environment state for one invocation."""

    def __init__(
        self,
        home: str | None = None,
        *,
        log: bool = True,
        log_override: Log | None = None,
    ) -> None:
        self.home = os.path.expanduser(home or os.environ.get("HOME") or "~")
        self.directory = os.path.join(self.home, CONFIG_SUBDIR)
        self.certificates_dir = os.path.join(self.directory, CERTIFICATES_SUBDIR)
        self.log = log_override if log_override is not None else Log(self.directory, enabled=log)

    # --- paths ---------------------------------------------------------------------
    def path(self, *parts: str) -> str:
        return os.path.join(self.directory, *parts)

    def certificate_path(self, certificate_id: int) -> str:
        return os.path.join(self.certificates_dir, f"{certificate_id}.cer")

    def marker_path(self, name: str) -> str:
        return self.path(name)

    # --- environment ---------------------------------------------------------------
    def read_ambiente(self) -> int:
        """Resolve ``ambiente``; unreadable -> 2, out of range -> 2 with a log line."""
        raw = _first_line(self.path("ambiente"))
        if raw is None:
            return AMBIENTE_PRODUCTION
        value = c_strtol(raw, 10)
        if value >= 4:
            self.log("valor invalido para ambiente, usando valor 2 (producao)")
            return AMBIENTE_PRODUCTION
        return value

    def write_ambiente(self, value: int) -> None:
        """``setConfiguracaoArquivo("ambiente", str(value))``: no trailing newline."""
        self._write_config("ambiente", str(value))

    def host(self, ambiente: int) -> str:
        return HOSTS.get(ambiente, HOSTS[AMBIENTE_PRODUCTION])

    def machine_id_file(self, ambiente: int) -> str:
        return MACHINE_ID_FILES.get(ambiente, MACHINE_ID_FILES[AMBIENTE_PRODUCTION])

    def read_machine_id(self, ambiente: int) -> str:
        """``X-SMARTCERT-UUID``: first line of the per-environment file, verbatim.

        Missing/unreadable file -> empty string, exactly like the original.
        """
        raw = _first_line(self.path(self.machine_id_file(ambiente)))
        return raw or ""

    def write_machine_id(self, ambiente: int, value: str) -> None:
        """Persist the server-assigned id for ``ambiente`` (``maquinaId*``)."""
        self._write_config(self.machine_id_file(ambiente), value)

    # --- side effects --------------------------------------------------------------
    def _write_config(self, name: str, value: str) -> None:
        """``setConfiguracaoArquivo``: whole-file overwrite, IO failures only logged.

        ``FileWriter`` truncates and writes ``valor`` verbatim, so no newline is added.
        The directory is created first because the official client's platform layer does
        that before any write can happen.
        """
        try:
            os.makedirs(self.directory, exist_ok=True)
            with open(self.path(name), "w", encoding="utf-8") as handle:
                handle.write(value)
        except OSError as exc:
            self.log(f"Erro ao tentar salvar informacao no diretorio de configuracoes: {exc}")

    def mark_update_available(self) -> None:
        """``fopen(..., \"w\")`` + ``fputs(\"1\")``, no trailing newline."""
        try:
            with open(self.marker_path(UPDATE_NAME), "w", encoding="utf-8") as handle:
                handle.write("1")
        except OSError:
            pass

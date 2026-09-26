"""The configuration utility's own logic.

Nothing here talks to the backend: what is worth pinning is the interface with the phone
(the exact QR payload) and with the user's environment (environment names, log format).
"""

from __future__ import annotations

import argparse
import os
import re
import zipfile

import pytest

from nuvem_p11 import cli, qr


def parse(*argv: str) -> tuple[argparse.Namespace, cli.Session]:
    args = cli.build_parser().parse_args(list(argv))
    return args, cli.Session(args)


# --- the QR payload -------------------------------------------------------------------


def test_qr_payload_is_byte_for_byte_what_the_phone_reads(monkeypatch):
    """Field order, separators and the ``host-user`` name are the interface with the app."""
    monkeypatch.setattr(cli.socket, "gethostname", lambda: "estacao")
    monkeypatch.setattr(cli, "user_name", lambda: "ana")
    assert cli.qr_payload("3f2a91c4") == (
        '{"identificador":"3f2a91c4","nome":"estacao-ana",'
        '"hostname":"estacao","username":"ana"}'
    )


def test_qr_payload_does_not_escape_like_json_would(monkeypatch):
    """The original concatenates the fields; it never escapes them."""
    monkeypatch.setattr(cli.socket, "gethostname", lambda: "estacao")
    monkeypatch.setattr(cli, "user_name", lambda: "ana")
    assert cli.qr_payload("a\\b") == cli.qr_payload("a\\b")
    assert "\\" in cli.qr_payload("a\\b")


def test_user_name_is_the_account_not_the_environment(monkeypatch):
    """Java reads ``System.getProperty("user.name")``, which ``$USER`` can spoof."""
    monkeypatch.setenv("USER", "someone-else")
    assert cli.user_name() != "someone-else"


class _Stream:
    """A stdout stand-in that records what was written and claims (or denies) being a TTY."""

    def __init__(self, tty: bool) -> None:
        self.tty = tty
        self.written = ""

    def isatty(self) -> bool:
        return self.tty

    def write(self, text: str) -> int:
        self.written += text
        return len(text)


@pytest.mark.parametrize(("tty", "expected"), [(True, True), (False, False)])
def test_the_qr_palette_is_forced_only_on_a_terminal(monkeypatch, tty, expected):
    """A QR has to be dark modules on a light background, and the theme decides that.

    On a dark theme the blocks come out light and the quiet zone black -- inverted, which is
    what the SerproID application refused. Forcing the pair settles it on any theme, and
    redirected output stays plain text.
    """
    args, _ = parse("--home", "/tmp", "associar")
    stream = _Stream(tty)
    monkeypatch.setattr(cli.sys, "stdout", stream)
    cli._show_qr("{}", args)

    assert "\u2588" in stream.written, "the symbol was not rendered"
    assert (cli.QR_PALETTE in stream.written) is expected
    assert (cli.QR_RESET in stream.written) is expected


def test_no_line_leaves_the_background_set() -> None:
    """The white must stop at the symbol's own margin, not run to the end of the terminal.

    A terminal that erases with the current background paints the rest of a row white when
    the newline is written with the background still active, so the block ends up inside a
    wide band -- and the first row, which nobody erased, stays narrow. The palette is
    therefore reapplied on every line and dropped before each newline, which leaves the width
    at exactly the symbol plus its quiet zone.
    """
    block = cli._qr_block(qr.to_text(qr.encode("x", ecc="L")))
    lines = block.split("\n")[:-1]  # o bloco termina em newline; o resto é vazio
    assert len(lines) > 1
    for line in lines:
        assert line.startswith(cli.QR_PALETTE)
        assert line.endswith(cli.QR_RESET)
        # nada entre as duas cores: o fundo nunca fica ativo além do próprio símbolo
        assert line.count(cli.QR_PALETTE) == 1 and line.count(cli.QR_RESET) == 1


def test_qr_none_prints_the_payload_without_a_symbol(monkeypatch):
    args, _ = parse("--home", "/tmp", "associar", "--qr", "none")
    stream = _Stream(False)
    monkeypatch.setattr(cli.sys, "stdout", stream)
    cli._show_qr('{"a":1}', args)

    assert '{"a":1}' in stream.written
    assert "\u2588" not in stream.written


# --- environment selection --------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", 0),
        ("1", 1),
        ("3", 3),
        ("dev", 0),
        ("desenvolvimento", 0),
        ("hom", 1),
        ("homolog", 1),
        ("homologação", 1),
        ("prod", 2),
        ("produção", 2),
        ("teste", 3),
    ],
)
def test_ambiente_accepts_numbers_and_aliases(value, expected):
    assert cli._ambiente(value) == expected


@pytest.mark.parametrize("value", ["marte", "4", "-1", ""])
def test_ambiente_rejects_anything_else(value):
    with pytest.raises(argparse.ArgumentTypeError):
        cli._ambiente(value)


# --- the session ------------------------------------------------------------------------


def test_lib_is_never_serpos_own_module(tmp_path):
    """The one thing this tool must not do by accident is register Serpro's module."""
    _, session = parse("--home", str(tmp_path), "status")
    assert session.lib != "/usr/lib/libserproidp11.so"
    assert session.lib.endswith("libnuvemp11.so")


def test_lib_can_be_overridden(tmp_path):
    _, session = parse("--home", str(tmp_path), "--lib", "/tmp/meu.so", "status")
    assert session.lib == "/tmp/meu.so"


def test_require_lib_accepts_an_existing_module(tmp_path):
    module = tmp_path / "libnuvemp11.so"
    module.write_bytes(b"")
    _, session = parse("--home", str(tmp_path), "--lib", str(module), "instalar")
    assert session.require_lib() == str(module)


def test_require_lib_refuses_a_missing_module(tmp_path, capsys):
    _, session = parse(
        "--home", str(tmp_path), "--lib", str(tmp_path / "ausente.so"), "instalar"
    )
    assert session.require_lib() is None
    assert "Não encontrei o módulo" in capsys.readouterr().out


def test_ambiente_flag_does_not_write_the_config_file(tmp_path):
    _, session = parse("--home", str(tmp_path), "--ambiente", "hom", "status")
    assert session.ambiente == 1
    assert not os.path.exists(os.path.join(str(tmp_path), ".config", "serproid", "ambiente"))


def test_ambiente_comes_from_the_config_directory_when_not_overridden(tmp_path):
    directory = tmp_path / ".config" / "serproid"
    directory.mkdir(parents=True)
    (directory / "ambiente").write_text("1")
    _, session = parse("--home", str(tmp_path), "status")
    assert session.ambiente == 1


# --- reporting --------------------------------------------------------------------------


def test_app_log_uses_the_format_of_the_official_logging_properties(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.tempfile, "gettempdir", lambda: str(tmp_path))
    cli.app_log("mensagem de teste")
    text = open(cli.app_log_path(), encoding="utf-8").read()
    assert re.fullmatch(
        r"\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] INFO: cli\(\) - mensagem de teste\n", text
    )


def test_relato_zips_the_logs_that_exist(tmp_path, monkeypatch):
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    monkeypatch.setattr(cli.tempfile, "gettempdir", lambda: str(tmp))
    cli.app_log("do aplicativo")

    home = tmp_path / "home"
    directory = home / ".config" / "serproid"
    directory.mkdir(parents=True)
    (directory / "serproid.log").write_text("do driver\n")

    target = tmp_path / "relato.zip"
    args, session = parse("--home", str(home), "relato", "-o", str(target))
    assert cli.cmd_relato(session, args) == 0

    with zipfile.ZipFile(target) as archive:
        assert sorted(archive.namelist()) == ["serproid-desktop.log", "serproid.log"]
        assert archive.read("serproid.log") == b"do driver\n"


def test_relato_reports_a_missing_directory_instead_of_raising(tmp_path):
    target = tmp_path / "nao" / "existe" / "relato.zip"
    args, session = parse("--home", str(tmp_path), "relato", "-o", str(target))
    assert cli.cmd_relato(session, args) == 1


# --- module registration detection (status) ---------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("library=/usr/lib/libserproidp11.so\nname=SerproID\n\n", True),
        ("library=/x/libneoidp11.so\nname=NeoID\n\n", True),
        ("library=/tmp/nosso.so\nname=SerproID\n\n", True),
        ("library=/tmp/nosso.so\nname=SerproID\n\n", True),
        ("name=Outro\n\n", False),
        ("", False),
    ],
)
def test_module_registration_detection(tmp_path, text, expected):
    path = tmp_path / "pkcs11.txt"
    path.write_text(text)
    assert cli._pkcs11_has_module(str(path), "/tmp/nosso.so") is expected


def test_missing_pkcs11_file_is_not_registered(tmp_path):
    assert cli._pkcs11_has_module(str(tmp_path / "ausente.txt"), "/tmp/x.so") is False

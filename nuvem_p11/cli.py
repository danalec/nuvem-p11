"""The SerproID configuration utility.

Console counterpart of the official JavaFX desktop: the same steps, the same backend
calls and the same browser configuration, but scriptable, dependency-free and usable over
SSH. The messages are the ones the original shows, so support scripts and user
expectations keep matching.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime

from . import browser, qr
from . import setup as installer
from .client import APP_OS, SerproIDClient
from .config import (
    AMBIENTE_DEV,
    AMBIENTE_HOMOLOG,
    AMBIENTE_PRODUCTION,
    AMBIENTE_TEST,
    VERSION,
    Config,
)
from .errors import BackendError, SerproIDError

AMBIENTE_NAMES = {
    AMBIENTE_DEV: "desenvolvimento",
    AMBIENTE_HOMOLOG: "homologação",
    AMBIENTE_PRODUCTION: "produção",
    AMBIENTE_TEST: "teste",
}

#: The project name, used in the usage line when the invocation gives us nothing better
#: (``python3 -m serproid`` has ``__main__.py`` as ``argv[0]``).
PROG = "nuvem-p11"

#: The original's own UI strings, reused verbatim.
MSG_INSTALL_APP = (
    "Antes de autorizar este computador para uso do certificado SerproID, você deve "
    "acessar a loja de aplicativos (Google Play ou App Store) e instalar o aplicativo "
    "SerproID."
)
MSG_SCAN = (
    "Inicie o SerproID no celular ou tablet, acesse a opção Computadores, toque na opção "
    "para adicionar, e faça a leitura do QR Code abaixo."
)
MSG_NO_CERTS = (
    "Este computador não possui certificados ativos associados. Acrescente seus "
    "certificados no aplicativo."
)
MSG_NOT_AUTHORIZED = (
    "Computador ainda não autorizado. Conclua os passos no aplicativo antes de prosseguir."
)
MSG_OUTDATED = (
    "Esta versão do SerproID Desktop está desatualizada, para continuar será preciso "
    "instalar a nova versão."
)
MSG_NETWORK = "Falha de comunicação. Verifique sua conexão com a internet e tente novamente."
MSG_GENERIC = (
    "Houve um erro inesperado ao se comunicar com o servidor. Tente novamente ou entre em "
    "contato com o suporte."
)
MSG_DONE = (
    "\nSeu computador está habilitado para uso do SerproID.\n"
    "Após reiniciar seu navegador, você pode usar o comando `testar` para verificar."
)
MSG_ANTIVIRUS = (
    "Atenção!\nCaso esteja utilizando um antivírus com proteção para internet "
    "(escaneamento HTTPS), inclua o domínio do SerproID (serproid.serpro.gov.br) na lista "
    "de exceções."
)
MSG_INSTALL_FAILED = (
    "Ocorreu um erro na instalação, favor gerar um arquivo para relato de erro e entrar "
    "em contato com o suporte."
)

TEST_URLS = {
    AMBIENTE_PRODUCTION: "https://ccd.serpro.gov.br/testeaqui",
}
TEST_URL_OTHER = "https://ecac.hom.receita.fazenda.gov.br/"

#: What ``browser.remove`` reports in ``details``, in words.
CHROME_STATES = {
    "absent": "nada a remover",
    "deleted": "módulo removido",
    "failed": "falhou",
    "present": "nssdb presente",
    "added": "módulo registrado",
    "already": "já estava registrado",
}


def app_log_path() -> str:
    """``%t/serproid-desktop.log`` -- the same place the official desktop logs to."""
    return os.path.join(tempfile.gettempdir(), "serproid-desktop.log")


def app_log(message: str) -> None:
    """Append in the format of the original's ``logging.properties``."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(app_log_path(), "a", encoding="utf-8") as handle:
            handle.write(f"[{stamp}] INFO: cli() - {message}\n")
    except OSError:
        pass


def user_name() -> str:
    """Java reads ``System.getProperty("user.name")``: the account, not ``$USER``."""
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, OSError):
        return os.environ.get("USER") or ""


def qr_payload(machine_id: str) -> str:
    """The exact JSON the original draws into the QR code, by concatenation as it does.

    Not through ``json.dumps``: the original builds the string field by field and sends it
    to the phone untouched, so the byte sequence is the interface.
    """
    host = socket.gethostname()
    user = user_name()
    return (
        '{"identificador":"'
        + machine_id
        + '","nome":"'
        + host
        + "-"
        + user
        + '","hostname":"'
        + host
        + '","username":"'
        + user
        + '"}'
    )


class Session:
    """Environment, config and client resolved once per invocation."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.home = os.path.expanduser(args.home or os.environ.get("HOME") or "~")
        self.config = Config(home=self.home, log=True)
        self.ambiente = (
            args.ambiente if args.ambiente is not None else self.config.read_ambiente()
        )
        self.host = self.config.host(self.ambiente)
        self.client = SerproIDClient(
            home=self.home,
            ambiente=self.ambiente,
            config=self.config,
        )

    @property
    def lib(self) -> str:
        """The module to register. Never Serpro's.

        Falls back to the conventional system path when nothing exists yet, so
        ``desinstalar`` can still strip a block whose file has already been removed.
        """
        return self.args.lib or browser.default_lib() or browser.SYSTEM_LIB

    def require_lib(self) -> str | None:
        """The module path, or ``None`` with the reason printed when it is not there."""
        lib = self.lib
        if os.path.exists(lib):
            return lib
        print(f"Não encontrei o módulo PKCS#11 em {lib}.")
        if not self.args.lib:
            print("Compile-o com `make` ou aponte com --lib CAMINHO.")
        return None

    def reload_machine_id(self) -> str:
        return self.config.read_machine_id(self.ambiente)


# --- commands -----------------------------------------------------------------------


def cmd_status(session: Session, args: argparse.Namespace) -> int:
    machine_id = session.reload_machine_id()
    certificates = []
    directory = session.config.certificates_dir
    if os.path.isdir(directory):
        certificates = sorted(name for name in os.listdir(directory) if name.endswith(".cer"))
    profiles = browser.firefox_profiles(session.home)
    registered = [
        profile
        for profile in profiles
        if _pkcs11_has_module(os.path.join(profile, "pkcs11.txt"), session.lib)
    ]
    nssdb = os.path.join(session.home, ".pki", "nssdb")

    if args.json:
        print(
            json.dumps(
                {
                    "ambiente": session.ambiente,
                    "ambiente_nome": AMBIENTE_NAMES.get(session.ambiente, "?"),
                    "host": session.host,
                    "maquinaId": machine_id,
                    "lib": session.lib,
                    "firefox_perfis": profiles,
                    "firefox_configurados": registered,
                    "chrome_nssdb": os.path.isdir(nssdb),
                    "certificados": certificates,
                    "versao": VERSION,
                    "so": APP_OS,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print(f"versão:      {VERSION} ({APP_OS})")
    print(f"ambiente:    {session.ambiente} ({AMBIENTE_NAMES.get(session.ambiente, '?')})")
    print(f"servidor:    {session.host}")
    print(f"máquina:     {machine_id or '(não registrada)'}")
    exists = "" if os.path.exists(session.lib) else "  [não existe: rode `make` ou use --lib]"
    print(f"módulo:      {session.lib}{exists}")
    print(f"Firefox:     {len(profiles)} perfil(is), {len(registered)} configurado(s)")
    for profile in profiles:
        mark = "configurado" if profile in registered else "NÃO configurado"
        print(f"  - {profile} [{mark}]")
    print(f"Chrome:      {'nssdb presente' if os.path.isdir(nssdb) else 'sem nssdb'}")
    print(f"certificados: {len(certificates)} em {directory}")
    for name in certificates:
        print(f"  - {name}")
    return 0


def cmd_associar(session: Session, args: argparse.Namespace) -> int:
    print(MSG_INSTALL_APP)
    print()
    print(f"Ambiente: {AMBIENTE_NAMES.get(session.ambiente, '?')} ({session.host})")
    print()
    # Deliberate deviation: the official desktop POSTs at every launch, and the backend
    # hands out a *new* identifier each time -- so merely opening it replaces the id this
    # machine was associated under and the module starts answering MAQ-NAO-AUT until the
    # QR is scanned again. Keeping the existing identifier makes a re-association re-bind
    # the same machine instead of orphaning it.
    machine_id = "" if args.registrar else session.reload_machine_id()
    if machine_id:
        print(f"Esta máquina já está registrada como {machine_id}.")
        print("O identificador existente será mantido.")
    else:
        app_log("cadastrando nova máquina")
        try:
            machine_id = session.client.register_machine()
        except SerproIDError as error:
            return _report(error)
        if not machine_id:
            print("O servidor não devolveu um identificador para esta máquina.")
            return 1
        # ``register_machine`` already persisted it under the environment's id file.
        print(f"Máquina registrada: {machine_id}")
    print()

    payload = qr_payload(machine_id)
    print(MSG_SCAN)
    print()
    _show_qr(payload, args)
    print()

    certificates = _await_association(session, args)
    if certificates is None:
        return 1
    return _install(session, args, certificates)


def _await_association(session: Session, args: argparse.Namespace):
    """Poll until the backend hands out certificates -- the original's "PRÓXIMO" loop."""
    interactive = sys.stdin.isatty()
    while True:
        try:
            payload = session.client.list_certificates()
        except BackendError as error:
            if str(error) == "MAQ-NAO-AUT":
                print(MSG_NOT_AUTHORIZED)
                payload = None  # keep polling; `payload` must stay bound for the check below
            elif str(error) == "VERSAO_APP_INCOMPATIVEL":
                print(MSG_OUTDATED)
                return None
            else:
                print(MSG_GENERIC)
                return None
        except SerproIDError:
            print(MSG_NETWORK)
            return None
        if payload:
            return payload
        if payload is not None:
            # A successful but empty answer. `None` means we already explained why (not authorized).
            print(MSG_NO_CERTS)
        if not interactive:
            print("(entrada não interativa: encerrando)")
            return None
        if args.wait:
            print(f"Aguardando {args.wait:g}s...")
            try:
                _sleep(args.wait)
            except KeyboardInterrupt:
                print()
                return None
            continue
        try:
            input("Pressione Enter para verificar novamente (Ctrl-C para sair). ")
        except (EOFError, KeyboardInterrupt):
            print()
            return None


def _sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)


def cmd_instalar(session: Session, args: argparse.Namespace) -> int:
    return _install(session, args, None)


def _install(
    session: Session, args: argparse.Namespace, payload: list[dict] | None
) -> int:
    lib = session.require_lib()
    if lib is None:
        return 1
    if payload is None:
        try:
            payload = session.client.list_certificates()
        except BackendError as error:
            code = str(error)
            if code == "MAQ-NAO-AUT":
                print(MSG_NOT_AUTHORIZED)
                print("Use `associar` para autorizar este computador primeiro.")
            elif code == "VERSAO_APP_INCOMPATIVEL":
                print(MSG_OUTDATED)
            else:
                print(MSG_GENERIC)
            return 1
        except SerproIDError:
            print(MSG_NETWORK)
            return 1
    certificates = installer.parse_certificates(payload)
    if not certificates:
        print(MSG_NO_CERTS)
        return 1
    print("Certificados:")
    for certificate in certificates:
        print(f"  - ({certificate.certificate_id}) {certificate.label}")
    print()
    app_log("instalando certificados")
    result = installer.install(
        session.config, certificates, home=session.home, lib=lib
    )
    print(f"- Certificado instalado com sucesso: {len(result.installed)}")
    for label, configured, product in (
        ("Firefox", result.firefox, "Firefox"),
        ("Chrome", result.chrome, "Chrome"),
    ):
        if configured is None:
            continue
        print(
            f"- {product} configurado com sucesso."
            if configured
            else f"- ATENÇÃO: Houve um erro na configuração do {product}."
        )
    updated = result.details.get("updated") or []
    if updated:
        # Worth saying out loud: these profiles were registered to another module -- the
        # official one, usually -- so they were silently loading nothing.
        print(
            f"  - {len(updated)} perfil(is) do Firefox apontavam para outro módulo"
            " e foram atualizados."
        )
    if result.details.get("chrome") == "updated":
        print("  - O módulo registrado no nssdb apontava para outro e foi substituído.")
    print(f"- Autoridades instaladas: {len(result.authorities)}")
    print()
    if result.ok:
        print(MSG_DONE)
        print()
        print(MSG_ANTIVIRUS)
    else:
        print(MSG_INSTALL_FAILED)
    return 0 if result.ok else 1


def cmd_desinstalar(session: Session, args: argparse.Namespace) -> int:
    result = browser.remove(session.home, lib=session.lib)
    app_log("removendo configuração dos navegadores")
    if result.firefox is False or result.chrome is False:
        print("Houve erro ao remover a configuração de algum navegador.")
        return 1
    removed = result.details.get("removed") or []
    if removed:
        print("Módulo removido dos perfis do Firefox:")
        for profile in removed:
            print(f"  - {profile}")
    else:
        print("Nenhum perfil do Firefox tinha o módulo registrado.")
    chrome = result.details.get("chrome")
    if chrome is not None:
        print(f"Chrome: {CHROME_STATES.get(chrome, chrome)}")
    print()
    print(f"Os certificados em {session.config.certificates_dir} foram mantidos.")
    print("Reinicie o navegador para que a remoção tenha efeito.")
    return 0


def cmd_testar(session: Session, args: argparse.Namespace) -> int:
    url = TEST_URLS.get(session.ambiente, TEST_URL_OTHER)
    if not _open(url):
        print(f"Abra esta página no navegador: {url}")
        return 0
    print(f"Abrindo {url}")
    print()
    print(MSG_ANTIVIRUS)
    return 0


def cmd_relato(session: Session, args: argparse.Namespace) -> int:
    """Zip the two logs, the same pair the official desktop collects.

    The module's log is the driver's own record -- what the caller asked, what the backend
    answered -- and the app log is ours. That is all it takes to follow a failure, and it is
    exactly what the official relato holds.
    """
    target = args.out or os.path.join(os.getcwd(), "relato-nuvem-p11.zip")
    sources = [app_log_path(), session.config.log.path]
    written = 0
    try:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            for source in sources:
                if not os.path.isfile(source):
                    continue
                archive.write(source, os.path.basename(source))
                written += 1
    except OSError as error:
        print(f"Ocorreu um erro, a geração do relato não foi concluída: {error}")
        return 1
    print(f"Relato gravado em {target} ({written} arquivo(s)).")
    return 0


# --- helpers ------------------------------------------------------------------------


def _pkcs11_has_module(path: str, lib: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return False
    lowered = text.lower()
    return "name=serproid" in lowered or "name=neoid" in lowered or lib in text


#: A QR symbol has to be dark modules on a light background with a light quiet zone. Which
#: way round the terminal paints our glyphs is up to its palette: on a dark theme the blocks
#: come out light and the quiet zone black, i.e. inverted, and readers that do not tolerate an
#: inverted symbol refuse it. Forcing the pair makes it right on any theme. Applied only when
#: we are writing to a terminal, so redirected output stays plain text.
QR_PALETTE = "\x1b[30;47m"
QR_RESET = "\x1b[0m"


def _qr_block(text: str) -> str:
    """The symbol with the palette set again on every line.

    Setting the colours once around the whole block leaves them active when the newline is
    written, and a terminal that erases with the background colour then paints the rest of
    every row white -- the symbol ends up inside a wide band, while the first row, which
    nobody erased, stays only as wide as the symbol: a ragged edge. Resetting before each
    newline makes every row exactly as wide as the symbol.
    """
    return "".join(
        f"{QR_PALETTE}{line}{QR_RESET}\n" for line in text.splitlines()
    )


def _show_qr(payload: str, args: argparse.Namespace) -> None:
    if args.qr == "none":
        print(f"Conteúdo do QR Code (digite no aplicativo): {payload}")
        return
    text = qr.to_text(qr.encode(payload, ecc=args.qr_ecc))
    if sys.stdout.isatty():
        print(_qr_block(text), end="")
    else:
        print(text, end="")


def _open(target: str) -> bool:
    opener = shutil.which("xdg-open")
    if not opener:
        return False
    try:
        subprocess.Popen(
            [opener, target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return False
    return True


def _report(error: Exception) -> int:
    code = str(error)
    if code == "VERSAO_APP_INCOMPATIVEL":
        print(MSG_OUTDATED)
    elif code in ("MAQ-NAO-AUT", "ERR-NAO-TRAT"):
        print(MSG_GENERIC)
    else:
        print(MSG_NETWORK)
    return 1


def _ambiente(value: str) -> int:
    aliases = {
        "dev": AMBIENTE_DEV,
        "desenvolvimento": AMBIENTE_DEV,
        "hom": AMBIENTE_HOMOLOG,
        "homolog": AMBIENTE_HOMOLOG,
        "homologacao": AMBIENTE_HOMOLOG,
        "homologação": AMBIENTE_HOMOLOG,
        "prod": AMBIENTE_PRODUCTION,
        "producao": AMBIENTE_PRODUCTION,
        "produção": AMBIENTE_PRODUCTION,
        "teste": AMBIENTE_TEST,
        "test": AMBIENTE_TEST,
    }
    lowered = value.strip().lower()
    if lowered in aliases:
        return aliases[lowered]
    try:
        number = int(lowered, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"ambiente inválido: {value}") from None
    if not 0 <= number <= 3:
        raise argparse.ArgumentTypeError(f"ambiente fora de 0..3: {value}")
    return number


def _prog() -> str:
    """What the user actually typed, so the usage line matches the invocation."""
    name = os.path.basename(sys.argv[0] or "")
    return name if name and name not in ("__main__.py", "-c") else PROG


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_prog(),
        description="Utilitário de configuração do SerproID (token em nuvem da Serpro).",
    )
    parser.add_argument(
        "--ambiente",
        type=_ambiente,
        help="0/desenvolvimento, 1/homologação, 2/produção (padrão), 3/teste. "
        "Só vale para esta execução; não grava o arquivo de configuração.",
    )
    parser.add_argument("--home", help="diretório HOME a usar (para testes)")
    parser.add_argument(
        "--lib",
        help="caminho do módulo PKCS#11 a registrar. O padrão é o primeiro que existir "
        "entre $NUVEM_P11_LIB, /usr/lib/libnuvemp11.so e shim/libnuvemp11.so — nunca o "
        "módulo da Serpro",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="mostra o estado da configuração")
    status.add_argument("--json", action="store_true", help="saída em JSON")
    status.set_defaults(func=cmd_status)

    associar = subparsers.add_parser(
        "associar", help="registra esta máquina e mostra o QR Code para o aplicativo"
    )
    associar.set_defaults(func=cmd_associar)
    associar.add_argument(
        "--registrar",
        action="store_true",
        help="pede um identificador NOVO ao servidor mesmo se a máquina já estiver "
        "registrada (pede um identificador novo, que precisa ser associado de novo)",
    )
    _add_qr_options(associar)
    associar.add_argument(
        "--wait",
        type=float,
        default=0.0,
        metavar="SEGUNDOS",
        help="em vez de pedir Enter, verifica sozinho a cada N segundos",
    )

    instalar = subparsers.add_parser(
        "instalar", help="busca e instala os certificados (máquina já autorizada)"
    )
    instalar.set_defaults(func=cmd_instalar)
    subparsers.add_parser(
        "sincronizar",
        help="o mesmo que `instalar` (o botão 'já autorizei esta máquina' do original)",
    ).set_defaults(func=cmd_instalar)

    subparsers.add_parser(
        "desinstalar", help="remove o módulo PKCS#11 dos navegadores"
    ).set_defaults(func=cmd_desinstalar)

    subparsers.add_parser("testar", help="abre a página de teste no navegador").set_defaults(
        func=cmd_testar
    )

    relato = subparsers.add_parser(
        "relato", help="gera um zip com os logs para relato de erro"
    )
    relato.set_defaults(func=cmd_relato)
    relato.add_argument("-o", "--out", help="arquivo .zip de saída")

    return parser


def _add_qr_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--qr",
        choices=("texto", "none"),
        default="texto",
        help="como exibir o QR Code: texto (padrão) ou none, só o conteúdo em uma linha",
    )
    parser.add_argument(
        "--qr-ecc",
        choices=("L", "M", "Q", "H"),
        default="L",
        help="nível de correção de erro do QR (padrão L, o mesmo do ZXing sem hints, "
        "que é o que o aplicativo oficial usa)",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    session = Session(args)
    app_log(f"SerproID {VERSION} - Ambiente: {session.ambiente} - SO: {APP_OS}")
    try:
        return args.func(session, args)
    except KeyboardInterrupt:
        print()
        return 130
    except SerproIDError as error:
        return _report(error)


if __name__ == "__main__":
    sys.exit(main())

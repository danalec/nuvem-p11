"""Browser integration: ``profiles.ini`` parsing, the ``pkcs11.txt`` block, the NSS commands.

Every test runs against a throwaway ``home`` and a fake runner that records argument vectors
instead of executing them, so ``modutil``/``certutil`` are never invoked and the real Firefox
profiles are never touched.
"""

from __future__ import annotations

import os
import subprocess

from nuvem_p11 import browser
from nuvem_p11.browser import LS, configure, firefox_profiles, install_ca_file, install_cas, remove

LIB = "/opt/nuvem-p11/shim/libnuvemp11.so"
BLOCK = f"library={LIB}{LS}name=SerproID{LS}{LS}"
AC_NAMES = [name for _, name in browser.AC_CERTS]


class FakeRunner:
    """Records command lines; ``-list`` answers with ``listing``."""

    def __init__(self, listing: str = "", returncode: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.listing = listing
        self.returncode = returncode

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        stdout = self.listing if "-list" in argv else ""
        return subprocess.CompletedProcess(argv, self.returncode, stdout, "")


def firefox_dir(home) -> str:
    return os.path.join(str(home), browser.FIREFOX_DIR)


def profile_dir(home, relpath: str, *, relative: bool = True) -> str:
    base = firefox_dir(home) if relative else str(home)
    path = os.path.join(base, relpath)
    os.makedirs(path, exist_ok=True)
    return path


def write_ini(home, sections: str) -> None:
    ini = os.path.join(str(home), browser.PROFILES_INI)
    os.makedirs(os.path.dirname(ini), exist_ok=True)
    with open(ini, "w", encoding="utf-8") as handle:
        handle.write(sections)


def write_pkcs11(profile: str, content: str) -> None:
    with open(os.path.join(profile, browser.PKCS11_FILE), "w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def read_pkcs11(profile: str) -> str:
    with open(os.path.join(profile, browser.PKCS11_FILE), encoding="utf-8", newline="") as handle:
        return handle.read()


def nssdb(home) -> str:
    path = os.path.join(str(home), browser.NSSDB)
    os.makedirs(path, exist_ok=True)
    return path


def profiles_ini(*profiles: tuple[str, bool]) -> str:
    lines = ["[General]", "StartWithLastProfile=1", ""]
    for index, (path, relative) in enumerate(profiles):
        lines += [f"[Profile{index}]", f"Name=profile{index}", f"IsRelative={int(relative)}", f"Path={path}", ""]
    return "\n".join(lines)


# --- 1. single profile, no pkcs11.txt -----------------------------------------------------


def test_missing_pkcs11_is_created_with_exactly_the_block(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))

    assert firefox_profiles(str(tmp_path)) == [profile]

    runner = FakeRunner()
    result = configure(str(tmp_path), lib=LIB, runner=runner)

    assert read_pkcs11(profile) == f"library={LIB}{LS}name=SerproID{LS}{LS}"
    assert result.firefox is True
    assert result.details["changed"] == [profile]
    assert result.details["firefox"] == "configured"


# --- 2. several profiles, one relative, one absolute, one ignored section ------------------


def test_every_profile_is_configured_and_other_sections_are_ignored(tmp_path):
    relative = profile_dir(tmp_path, "Profiles/rel.default")
    absolute = profile_dir(tmp_path, "abs.default", relative=False)
    write_ini(
        tmp_path,
        """
[General]
StartWithLastProfile=1

[Profile0]
Name=default
IsRelative=1
Path=Profiles/rel.default

[Profile1]
Name=absolute
IsRelative=0
Path={absolute}

[Install1234]
Default=Profiles/rel.default
IsRelative=1
Path=Profiles/rel.default

[Profile2]
Name=deleted
IsRelative=1
Path=Profiles/gone.default
""".format(absolute=absolute),
    )

    # The "[Install…]" section also has a Path; only "[Profile…]" sections count. The third
    # profile points at a directory that does not exist, so there is nothing to write into it.
    assert firefox_profiles(str(tmp_path)) == [
        relative,
        absolute,
        os.path.join(firefox_dir(tmp_path), "Profiles/gone.default"),
    ]

    result = configure(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert read_pkcs11(relative) == BLOCK
    assert read_pkcs11(absolute) == BLOCK
    assert not os.path.exists(os.path.join(firefox_dir(tmp_path), "Profiles", "gone.default"))
    assert result.firefox is True
    assert result.details["changed"] == [relative, absolute]
    assert result.details["missing"] == [os.path.join(firefox_dir(tmp_path), "Profiles/gone.default")]


def test_profiles_ini_absent_means_no_firefox_work(tmp_path):
    assert firefox_profiles(str(tmp_path)) == []
    result = configure(str(tmp_path), lib=LIB, runner=FakeRunner())
    assert result.firefox is None
    assert result.details["firefox"] == "absent"


# --- 3/4. already configured -----------------------------------------------------------------


def test_existing_serproid_block_is_not_duplicated(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))
    before = f"library={LIB}{LS}name=SerproID{LS}{LS}"
    write_pkcs11(profile, before)

    runner = FakeRunner()
    result = configure(str(tmp_path), lib=LIB, runner=runner)

    assert read_pkcs11(profile) == before
    assert result.firefox is True
    assert result.details["firefox"] == "already"
    assert result.details["present"] == [profile]
    assert result.details["changed"] == []


def test_existing_neoid_block_is_not_touched(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))
    before = f"library=/usr/lib/libneoidp11.so{LS}name=NeoID{LS}{LS}"
    write_pkcs11(profile, before)

    result = configure(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert read_pkcs11(profile) == before
    assert result.details["firefox"] == "already"


# --- 3b. registered under our name, pointing somewhere else -----------------------------------


def test_foreign_serproid_path_is_rewritten(tmp_path):
    """What the official desktop leaves behind: the right name, a path that may be gone.

    Skipping on the name alone -- enough for the official helper, which is the only thing that
    ever wrote the file -- leaves the browser loading ``/usr/lib/libserproidp11.so`` after that
    package is removed. NSS then finds no module, no certificate reaches the handshake, and the
    test page reports that the certificate could not be validated.
    """
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))
    write_pkcs11(profile, f"library=/usr/lib/libserproidp11.so{LS}name=SerproID{LS}{LS}")

    result = configure(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert read_pkcs11(profile) == f"library={LIB}{LS}name=SerproID{LS}{LS}"
    assert result.firefox is True
    assert result.details["firefox"] == "configured"
    assert result.details["updated"] == [profile]
    assert result.details["changed"] == []


def test_rewriting_leaves_the_other_modules_alone(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))
    other = f"library=/usr/lib/opensc-pkcs11.so{LS}name=OpenSC{LS}{LS}"
    write_pkcs11(profile, f"{other}library=/usr/lib/libserproidp11.so{LS}name=SerproID{LS}{LS}")

    configure(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert read_pkcs11(profile) == f"{other}library={LIB}{LS}name=SerproID{LS}{LS}"


def test_rewritten_registration_can_still_be_removed(tmp_path):
    """The rewrite keeps our name, so ``remove`` still recognises the block it wrote."""
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))
    write_pkcs11(profile, f"library=/usr/lib/libserproidp11.so{LS}name=SerproID{LS}{LS}")

    configure(str(tmp_path), lib=LIB, runner=FakeRunner())
    remove(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert not os.path.exists(os.path.join(profile, "pkcs11.txt"))


# --- 5. append preserves whatever was there --------------------------------------------------


def test_append_preserves_a_pre_existing_module(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))
    before = f"library=/usr/lib/opensc-pkcs11.so{LS}name=OpenSC{LS}"
    write_pkcs11(profile, before)

    configure(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert read_pkcs11(profile) == before + BLOCK


def test_append_inserts_the_separator_the_previous_line_lacks(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))
    write_pkcs11(profile, "library=/usr/lib/opensc-pkcs11.so\nname=OpenSC")

    configure(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert read_pkcs11(profile) == f"library=/usr/lib/opensc-pkcs11.so{LS}name=OpenSC{LS}" + BLOCK


# --- 6/7. Chromium / the shared NSS database --------------------------------------------------


def test_absent_nssdb_skips_chrome_and_runs_nothing(tmp_path):
    runner = FakeRunner()

    result = configure(str(tmp_path), lib=LIB, runner=runner)

    assert result.chrome is None
    assert result.details["chrome"] == "absent"
    assert result.details["nssdb"] is None
    assert runner.calls == []


def test_nssdb_is_listed_then_the_module_is_added(tmp_path):
    db = nssdb(tmp_path)
    runner = FakeRunner()

    result = configure(str(tmp_path), lib=LIB, runner=runner)

    assert runner.calls == [
        ["modutil", "-list", "-dbdir", f"sql:{db}"],
        ["modutil", "-force", "-add", "SerproID", "-dbdir", f"sql:{db}", "-libfile", LIB],
    ]
    assert result.chrome is True
    assert result.details["chrome"] == "added"
    assert result.details["nssdb"] == db


def test_listing_that_already_mentions_serproid_only_lists(tmp_path):
    db = nssdb(tmp_path)
    runner = FakeRunner(listing=f"2 modules in the database:\n1. NSS Internal PKCS #11 Module\n2. SerproID\n")

    result = configure(str(tmp_path), lib=LIB, runner=runner)

    assert runner.calls == [["modutil", "-list", "-dbdir", f"sql:{db}"]]
    assert result.chrome is True
    assert result.details["chrome"] == "present"


def test_listing_that_mentions_neoid_only_lists(tmp_path):
    db = nssdb(tmp_path)
    runner = FakeRunner(listing="2. NeoID\n")

    result = configure(str(tmp_path), lib=LIB, runner=runner)

    assert result.details["chrome"] == "present"
    assert runner.calls == [["modutil", "-list", "-dbdir", f"sql:{db}"]]


def test_nssdb_entry_pointing_elsewhere_is_replaced(tmp_path):
    """``modutil -list`` prints the registered path, so a stale one is there to be read.

    The name being present is not enough: after the official package is removed its entry
    stays, pointing at a library that no longer exists. ``-force -add`` refuses to replace such
    an entry -- "Failure to load dynamic library" -- so the entry is turned over first.
    """
    db = nssdb(tmp_path)
    listing = (
        "Listing of PKCS #11 Modules\n"
        "-----------------------------------------------------------\n"
        "  1. NSS Internal PKCS #11 Module\n"
        "\tlibrary name: /usr/lib/libnss3.so\n"
        "  2. SerproID\n"
        "\tlibrary name: /usr/lib/libserproidp11.so\n"
    )
    runner = FakeRunner(listing=listing)

    result = configure(str(tmp_path), lib=LIB, runner=runner)

    assert runner.calls == [
        ["modutil", "-list", "-dbdir", f"sql:{db}"],
        ["modutil", "-delete", "SerproID", "-dbdir", f"sql:{db}"],
        ["modutil", "-force", "-add", "SerproID", "-dbdir", f"sql:{db}", "-libfile", LIB],
    ]
    assert result.chrome is True
    assert result.details["chrome"] == "updated"


def test_nssdb_entry_already_pointing_at_ours_is_left_alone(tmp_path):
    db = nssdb(tmp_path)
    runner = FakeRunner(listing=f"  2. SerproID\n\tlibrary name: {LIB}\n")

    result = configure(str(tmp_path), lib=LIB, runner=runner)

    assert runner.calls == [["modutil", "-list", "-dbdir", f"sql:{db}"]]
    assert result.details["chrome"] == "present"


def test_failed_modutil_add_is_reported(tmp_path):
    nssdb(tmp_path)

    result = configure(str(tmp_path), lib=LIB, runner=FakeRunner(returncode=1))

    assert result.chrome is False
    assert result.details["chrome"] == "failed"


# --- 8. the certificates -----------------------------------------------------------------------


def test_install_cas_uses_the_exact_certutil_command_lines(tmp_path):
    relative = profile_dir(tmp_path, "Profiles/rel.default")
    legacy = profile_dir(tmp_path, "Profiles/legacy.default")
    db = nssdb(tmp_path)
    touch(relative, "cert9.db")
    touch(legacy, "cert8.db")
    write_ini(
        tmp_path,
        profiles_ini(("Profiles/rel.default", True), ("Profiles/legacy.default", True)),
    )

    runner = FakeRunner()
    installed = install_cas(str(tmp_path), runner=runner)

    expected = []
    for filename, name in browser.AC_CERTS:
        for database in (f"sql:{relative}", legacy, f"sql:{db}"):
            expected.append(
                [
                    "certutil", "-A", "-n", name, "-d", database, "-t", "CT,C,C",
                    "-i", os.path.join(browser.AC_DIR, filename),
                ]
            )
    assert runner.calls == expected
    assert installed == AC_NAMES
    assert [f for f, _ in browser.AC_CERTS] == [
        "ICP-Brasil.crt",
        "ICP-Brasilv2.crt",
        "ICP-Brasilv5.crt",
        "acserprov4.crt",
        "acserproacfv5.crt",
    ]
    assert [n for _, n in browser.AC_CERTS] == [
        "Autoridade Certificadora Raiz Brasileira v1",
        "Autoridade Certificadora Raiz Brasileira v2",
        "Autoridade Certificadora Raiz Brasileira v5",
        "Autoridade Certificadora SERPRO v4",
        "Autoridade Certificadora do SERPRO Final v5",
    ]
    for filename, _ in browser.AC_CERTS:
        assert os.path.exists(os.path.join(browser.AC_DIR, filename))


def test_cert8_database_is_addressed_without_the_sql_prefix(tmp_path):
    legacy = profile_dir(tmp_path, "Profiles/legacy.default")
    touch(legacy, "cert8.db")
    write_ini(tmp_path, profiles_ini(("Profiles/legacy.default", True)))

    runner = FakeRunner()
    install_cas(str(tmp_path), runner=runner)

    assert all(call[call.index("-d") + 1] == legacy for call in runner.calls)
    assert len(runner.calls) == len(browser.AC_CERTS)


def test_install_ca_file_targets_every_database_with_the_given_name(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/rel.default")
    db = nssdb(tmp_path)
    touch(profile, "cert9.db")
    write_ini(tmp_path, profiles_ini(("Profiles/rel.default", True)))

    runner = FakeRunner()
    databases = install_ca_file(
        str(tmp_path),
        "Autoridade Certificadora SERPRO v3",
        "/tmp/chain-1.der",
        runner=runner,
    )

    assert databases == [f"sql:{profile}", f"sql:{db}"]
    assert runner.calls == [
        [
            "certutil", "-A", "-n", "Autoridade Certificadora SERPRO v3", "-d", f"sql:{profile}",
            "-t", "CT,C,C", "-i", "/tmp/chain-1.der",
        ],
        [
            "certutil", "-A", "-n", "Autoridade Certificadora SERPRO v3", "-d", f"sql:{db}",
            "-t", "CT,C,C", "-i", "/tmp/chain-1.der",
        ],
    ]


def test_install_cas_without_any_database_is_a_no_op(tmp_path):
    runner = FakeRunner()

    assert install_cas(str(tmp_path), runner=runner) == []
    assert runner.calls == []


def test_failed_certutil_is_not_reported_as_installed(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/rel.default")
    touch(profile, "cert9.db")
    write_ini(tmp_path, profiles_ini(("Profiles/rel.default", True)))

    assert install_cas(str(tmp_path), runner=FakeRunner(returncode=1)) == []


def touch(profile: str, filename: str) -> None:
    open(os.path.join(profile, filename), "w").close()


# --- 9. removal ---------------------------------------------------------------------------------


def test_remove_restores_the_previous_content_and_is_idempotent(tmp_path):
    touched = profile_dir(tmp_path, "Profiles/touched.default")
    fresh = profile_dir(tmp_path, "Profiles/fresh.default")
    write_ini(
        tmp_path,
        profiles_ini(("Profiles/touched.default", True), ("Profiles/fresh.default", True)),
    )
    before = f"library=/usr/lib/opensc-pkcs11.so{LS}name=OpenSC{LS}"
    write_pkcs11(touched, before)

    configure(str(tmp_path), lib=LIB, runner=FakeRunner())
    assert read_pkcs11(touched) == before + BLOCK
    assert read_pkcs11(fresh) == BLOCK

    result = remove(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert read_pkcs11(touched) == before
    assert not os.path.exists(os.path.join(fresh, browser.PKCS11_FILE))
    assert result.firefox is True
    assert result.details["removed"] == [touched, fresh]

    before_second = read_pkcs11(touched)
    again = remove(str(tmp_path), lib=LIB, runner=FakeRunner())
    assert read_pkcs11(touched) == before_second
    assert not os.path.exists(os.path.join(fresh, browser.PKCS11_FILE))
    assert again.firefox is True
    assert again.details["removed"] == []

    configure(str(tmp_path), lib=LIB, runner=FakeRunner())
    assert read_pkcs11(touched) == before + BLOCK


def test_remove_deletes_the_nss_module_only_when_it_is_listed(tmp_path):
    db = nssdb(tmp_path)
    runner = FakeRunner(listing="2. SerproID\n")

    result = remove(str(tmp_path), lib=LIB, runner=runner)

    assert runner.calls == [
        ["modutil", "-list", "-dbdir", f"sql:{db}"],
        ["modutil", "-dbdir", f"sql:{db}", "-delete", "SerproID"],
    ]
    assert result.chrome is True
    assert result.details["chrome"] == "deleted"


def test_remove_without_the_module_or_the_nssdb(tmp_path):
    runner = FakeRunner(listing="1. NSS Internal PKCS #11 Module\n")

    assert remove(str(tmp_path), lib=LIB, runner=runner).chrome is None
    assert runner.calls == []

    db = nssdb(tmp_path)
    runner = FakeRunner(listing="1. NSS Internal PKCS #11 Module\n")
    result = remove(str(tmp_path), lib=LIB, runner=runner)

    assert runner.calls == [["modutil", "-list", "-dbdir", f"sql:{db}"]]
    assert result.chrome is True
    assert result.details["chrome"] == "absent"


def test_remove_leaves_a_block_of_another_library_alone(tmp_path):
    profile = profile_dir(tmp_path, "Profiles/abc.default")
    write_ini(tmp_path, profiles_ini(("Profiles/abc.default", True)))
    other = f"library=/usr/lib/opensc-pkcs11.so{LS}name=SerproID{LS}{LS}"
    write_pkcs11(profile, other)

    remove(str(tmp_path), lib=LIB, runner=FakeRunner())

    assert read_pkcs11(profile) == other

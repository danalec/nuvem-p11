"""QR encoder tests.

Two independent oracles. The strongest is ZXing 3.3.0 -- the encoder inside the official
SerproID client -- whose symbols are pinned as golden digests: same version, same mask,
same modules. The authoritative functional check is the decoder round trip: ``zbarimg``
must read a byte-identical payload back out of the generated PNG. The geometry tests pin
the versions and the text render size, and the structural tests pin the function patterns
that a decoder needs.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import zlib

import pytest

from nuvem_p11 import qr

ZBARIMG = shutil.which("zbarimg")

#: Enrollment payload in the shape the backend delivers. Synthetic values, but exactly
#: 115 bytes like a real one: the length is what picks version 6 at level L, so the
#: geometry assertions below depend on it.
REAL = (
    '{"identificador":"3f2a91c4e0b74d8a5c1f6e2d9b0a7c4e18d5f3a2",'
    '"nome":"estacao-ana","hostname":"lab","username":"ana"}'
)

_LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "

#: Latin-1 bytes of the accented sample: ``ô``/``é`` are single bytes and the em dash,
#: which is not in Latin-1, becomes ``?`` -- the same bytes ZXing encodes.
ACCENTED_LATIN1 = b"Assinatura eletr\xf4nica ? Jos\xe9"

#: The exact bytes handed to the encoder. Every case here is valid UTF-8, which zbarimg
#: hands back verbatim; the Latin-1 case has its own test because zbar converts it.
PAYLOADS = {
    "short": b"oi",
    "accented_utf8": "Assinatura eletrônica — José".encode("utf-8"),
    "long": (_LOREM * 9)[:500].encode("ascii"),
    "very_long": (_LOREM * 20)[:1000].encode("ascii"),
    "real": REAL.encode("ascii"),
}

LEVELS = ("L", "M", "Q", "H")


def decode(png: bytes, tmp_path) -> bytes:
    """Payload as read back by zbarimg, which fails loudly when it cannot decode."""
    path = tmp_path / "symbol.png"
    path.write_bytes(png)
    result = subprocess.run(
        [ZBARIMG, "-q", "--raw", str(path)], capture_output=True, check=True
    )
    return result.stdout.rstrip(b"\n")


def finder_at(modules, ox: int, oy: int) -> bool:
    """Whether the 7x7 block at ``(ox, oy)`` is a finder pattern."""
    for dy in range(7):
        for dx in range(7):
            want = dx in (0, 6) or dy in (0, 6) or (2 <= dx <= 4 and 2 <= dy <= 4)
            if modules[oy + dy][ox + dx] != want:
                return False
    return True


@pytest.mark.skipif(ZBARIMG is None, reason="zbarimg is required to decode QR symbols")
@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_zbarimg_round_trip(name: str, level: str, tmp_path) -> None:
    payload = PAYLOADS[name]
    matrix = qr.encode(payload, ecc=level)
    assert decode(qr.to_png(matrix), tmp_path) == payload


#: The literal glyphs, written out rather than taken from the renderer: a test that reads the
#: renderer's own constant would happily follow it into an inverted polarity.
_PAINT_BOTH, _PAINT_UPPER, _PAINT_LOWER, _PAINT_NONE = "\u2588", "\u2580", "\u2584", " "

#: Top-left finder pattern, in module coordinates.
_FINDER = ("1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111")


def painted(glyph: str, upper: bool) -> bool:
    """Whether the terminal paints the given half of the cell for this glyph."""
    if glyph == _PAINT_BOTH:
        return True
    if glyph == _PAINT_UPPER:
        return upper
    if glyph == _PAINT_LOWER:
        return not upper
    return False


def test_text_render_paints_the_dark_modules() -> None:
    """A QR is dark modules on a light background, and the terminal paints the glyphs.

    The CLI therefore forces a black foreground on a white background; if the renderer
    swapped the glyphs the symbol would come out inverted and readers refuse it -- the
    SerproID application among them. The finder pattern is the anchor: it is the same in
    every symbol, whatever the mask.
    """
    quiet = 4
    lines = qr.to_text(qr.encode(REAL, ecc="L"), quiet=quiet).rstrip("\n").split("\n")
    for y in range(7):
        for x in range(7):
            glyph = lines[(y + quiet) // 2][x + quiet]
            assert painted(glyph, y % 2 == 0) is (_FINDER[y][x] == "1"), f"module ({x},{y})"


def modules_from_text(text: str) -> list[list[bool]]:
    """Read the render back as a terminal shows it: one text line covers two module rows."""
    rows: list[list[bool]] = []
    for line in text.rstrip("\n").split("\n"):
        rows.append([painted(glyph, True) for glyph in line])
        rows.append([painted(glyph, False) for glyph in line])
    return rows


@pytest.mark.skipif(ZBARIMG is None, reason="zbarimg is required to decode QR symbols")
def test_text_render_is_the_symbol_and_decodes(tmp_path) -> None:
    """What the user actually points a phone at gets decoded back, not just inspected.

    Reading the glyphs back catches a dropped half-row or a broken quiet zone, and zbarimg
    catches the polarity, since it wants dark on light. Without this, a render that is
    merely pretty but inverted -- or subtly shifted -- passes every other test here.
    """
    quiet = 4
    matrix = qr.encode(REAL, ecc="L")
    span = matrix.size + 2 * quiet
    rows = modules_from_text(qr.to_text(matrix, quiet=quiet))

    assert len(rows) >= span
    assert all(len(row) == span for row in rows)
    for y in range(span):
        for x in range(span):
            inside = quiet <= y < quiet + matrix.size and quiet <= x < quiet + matrix.size
            expected = matrix.modules[y - quiet][x - quiet] if inside else False
            assert rows[y][x] is expected, f"module ({x},{y})"

    symbol = qr.Matrix(
        size=span,
        version=matrix.version,
        ecc=matrix.ecc,
        mask=matrix.mask,
        modules=tuple(tuple(row) for row in rows[:span]),
    )
    assert decode(qr.to_png(symbol, scale=8, quiet=0), tmp_path) == REAL.encode()


def test_real_payload_at_level_l_matches_the_reference_render() -> None:
    """Level L is qrencode's default and the level ZXing picks without hints: 49x25."""
    matrix = qr.encode(REAL, ecc="L")
    assert (matrix.version, matrix.size) == (6, 41)

    lines = qr.to_text(matrix).splitlines()
    assert len(lines) == 25
    assert {len(line) for line in lines} == {49}


def test_real_payload_at_level_m_is_version_seven() -> None:
    """Version 6 at level M holds 106 bytes and the payload is 115, so M needs 45x45."""
    matrix = qr.encode(REAL, ecc="M")
    assert (matrix.version, matrix.size) == (7, 45)

    lines = qr.to_text(matrix).splitlines()
    assert len(lines) == 27
    assert {len(line) for line in lines} == {53}


def test_real_payload_versions_per_level() -> None:
    expected = {"L": (6, 41), "M": (7, 45), "Q": (9, 53), "H": (10, 57)}
    for level, (version, size) in expected.items():
        matrix = qr.encode(REAL, ecc=level)
        assert (matrix.version, matrix.size) == (version, size)


def test_default_quiet_zone_is_four_modules_on_both_renderers() -> None:
    matrix = qr.encode(REAL, ecc="L")

    lines = qr.to_text(matrix).splitlines()
    assert qr.to_text(matrix).endswith("\n")
    assert all(len(line) == matrix.size + 8 for line in lines)
    assert lines[0] == " " * (matrix.size + 8)  # quiet rows above the symbol
    assert all(line.startswith("    ") and line.endswith("    ") for line in lines)

    width, height = struct.unpack(">II", qr.to_png(matrix)[16:24])
    assert (width, height) == ((matrix.size + 8) * 8,) * 2  # default scale 8


def test_png_container_is_well_formed() -> None:
    matrix = qr.encode("oi")
    png = qr.to_png(matrix, scale=3, quiet=2)
    assert png.startswith(b"\x89PNG\r\n\x1a\n")

    chunks: list[tuple[bytes, bytes]] = []
    offset = 8
    while offset < len(png):
        (length,) = struct.unpack(">I", png[offset : offset + 4])
        tag = png[offset + 4 : offset + 8]
        data = png[offset + 8 : offset + 8 + length]
        (crc,) = struct.unpack(">I", png[offset + 8 + length : offset + 12 + length])
        assert crc == zlib.crc32(tag + data) & 0xFFFFFFFF
        chunks.append((tag, data))
        offset += 12 + length
    assert offset == len(png)
    assert [tag for tag, _ in chunks] == [b"IHDR", b"IDAT", b"IEND"]

    header = struct.unpack(">IIBBBBB", chunks[0][1])
    assert header[:2] == ((matrix.size + 4) * 3,) * 2
    assert header[2:] == (8, 0, 0, 0, 0)  # 8-bit greyscale, deflate, no interlace
    side = (matrix.size + 4) * 3
    assert len(zlib.decompress(chunks[1][1])) == side * (side + 1)  # filter byte per row


def test_finders_timing_and_dark_module() -> None:
    matrix = qr.encode(REAL, ecc="L")
    size = matrix.size
    for origin in ((0, 0), (size - 7, 0), (0, size - 7)):
        assert finder_at(matrix.modules, *origin)
    # The bottom-right corner is data by design: a QR symbol only has three finders.
    assert not finder_at(matrix.modules, size - 7, size - 7)

    # Separators: the one-module ring between each finder and the encoding region.
    for i in range(8):
        assert matrix.get(7, i) is False
        assert matrix.get(i, 7) is False
        assert matrix.get(size - 8, i) is False
        assert matrix.get(size - 1 - i, 7) is False
        assert matrix.get(7, size - 1 - i) is False
        assert matrix.get(i, size - 8) is False

    for i in range(8, size - 8):
        assert matrix.modules[6][i] == (i % 2 == 0)
        assert matrix.modules[i][6] == (i % 2 == 0)

    assert matrix.get(8, size - 8) is True  # the always-dark module


@pytest.mark.parametrize("version", range(1, 41))
def test_size_and_finders_for_every_version(version: int) -> None:
    matrix = qr.encode("oi", min_version=version)
    assert matrix.version == version
    assert matrix.size == 4 * version + 17
    assert matrix.size % 4 == 1
    for origin in ((0, 0), (matrix.size - 7, 0), (0, matrix.size - 7)):
        assert finder_at(matrix.modules, *origin)


def test_version_six_byte_capacity_boundaries() -> None:
    """Byte mode with an 8-bit count indicator: version 6 holds 134/106/74/58 bytes."""
    for level, capacity in (("L", 134), ("M", 106), ("Q", 74), ("H", 58)):
        assert qr.encode(b"A" * capacity, ecc=level).version == 6
        assert qr.encode(b"A" * (capacity + 1), ecc=level).version == 7


#: Modules left over after the last codeword, per version (ISO/IEC 18004 table 1).
REMAINDER_BITS = {
    **{1: 0},
    **{version: 7 for version in range(2, 7)},
    **{version: 0 for version in range(7, 14)},
    **{version: 3 for version in range(14, 21)},
    **{version: 4 for version in range(21, 28)},
    **{version: 3 for version in range(28, 35)},
    **{version: 0 for version in range(35, 41)},
}


@pytest.mark.parametrize("version", range(1, 41))
def test_rs_tables_match_the_module_geometry(version: int) -> None:
    """Every level's data+EC codewords must exactly fill the data modules of the symbol."""
    data_modules = qr._data_module_count(version)
    for level in LEVELS:
        ec_per_block, structure = qr._RS_BLOCKS[(version, level)]
        total = ec_per_block * sum(count for count, _ in structure) + sum(
            count * size for count, size in structure
        )
        assert data_modules == 8 * total + REMAINDER_BITS[version]


def test_min_version_forces_a_larger_symbol() -> None:
    assert qr.encode("oi").version == 1
    assert qr.encode("oi", min_version=9).version == 9
    assert qr.encode("oi", ecc="H", min_version=40).version == 40


def test_invalid_arguments_are_rejected() -> None:
    with pytest.raises(ValueError):
        qr.encode("oi", ecc="X")
    with pytest.raises(ValueError):
        qr.encode("oi", min_version=41)
    with pytest.raises(ValueError):
        qr.encode(b"A" * 3000, ecc="H")
    with pytest.raises(ValueError):
        qr.to_text(qr.encode("oi"), light="XY")


#: Symbols produced by ZXing 3.3.0 -- ``com.google.zxing.qrcode.encoder.Encoder``, the
#: encoder inside the official SerproID client -- keyed by (payload, level):
#: ``(version, size, mask, sha256 of the row-major "0"/"1" matrix)``.
ZXING_GOLDEN = {
    ("real", "L"): (6, 41, 4, "5ed97b8ef2f206149adf200730b70e84380341cf0ed9363bf1d5db7ee4d03ed9"),
    ("real", "M"): (7, 45, 2, "812bed48f7baa20688d2ecd4ac108886fdfe5a32d6ffd6ee200423e741c6cb11"),
    ("real", "Q"): (9, 53, 4, "d72facd254bb2979518d54f5e7d9fdc4bd795100d6fd6c2a5a82e2d038acf661"),
    ("real", "H"): (10, 57, 2, "92b763effda2ea657f6c5a159669c85672d04e63041a9992a9dc8d725e7b901f"),
    ("short", "L"): (1, 21, 7, "f8c9d006b65ebc26134be37d9a1784c86bfe4c7ac423a07bf7edd9a1d5ea1085"),
    ("short", "M"): (1, 21, 3, "c3ef656fc5a64d1e0a314b819d0532bf03c72e4ddc844a65364b4be045db6259"),
    ("short", "Q"): (1, 21, 7, "83473112188aa597a3aecef001f54bd8e8dd01da790bdefe02e54b2360151c71"),
    ("short", "H"): (1, 21, 1, "0ff01b25caae1a59d2c901913977e94ee858850ff88ad27c94fdfec1c612c566"),
    ("accented", "L"): (2, 25, 7, "72458ab7df9e61c7492d7b9b0f5b49ad451ce9e304d4ec3fdd139ba5152122de"),
    ("accented", "M"): (3, 29, 3, "99c288cf163ee9db438f7931587b7b9b35d7e2533f90cbac323ff7571b8e93ec"),
    ("accented", "Q"): (3, 29, 0, "0869c5b9b9eb1e1abcb8290c386e1e271d6ada987530e39cc7b489ced9b0abdc"),
    ("accented", "H"): (4, 33, 2, "72e3eb3808f2654e565d4da50b17071bd65d75a68eed13adf8e92cdb8520a1e3"),
    ("long", "L"): (9, 53, 0, "cfe4fcc3cbfb75bae459f5b5755931f4e90efa22627918ac07302a383974300e"),
    ("long", "M"): (10, 57, 2, "c8294f9a437b1546845ed5dde9c2fef56432bd243e9267501998ce08c0151b59"),
    ("long", "Q"): (12, 65, 0, "007d9e4428db8cbb0bbcdc18cda569363418457043a9e31f8db2e17238c18919"),
    ("long", "H"): (15, 77, 7, "e90217762934b4c3b47a11def805bdb536c280447066f3332b47bc8c741c08d1"),
}

#: The payloads in the exact bytes ZXing was fed: ZXing's byte-mode charset defaults to
#: ISO-8859-1 (``Encoder.DEFAULT_BYTE_MODE_ENCODING``), and ``encode`` maps ``str`` the
#: same way, so the ``str`` forms below reproduce the reference symbols.
ZXING_PAYLOADS = {
    "real": REAL,
    "short": "oi",
    "accented": "Assinatura eletrônica — José",
    "long": "x" * 200,
}


def digest(matrix: qr.Matrix) -> str:
    flat = "".join("1" if module else "0" for row in matrix.modules for module in row)
    return hashlib.sha256(flat.encode()).hexdigest()


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("name", sorted(ZXING_PAYLOADS))
def test_symbol_is_identical_to_zxing_3_3_0(name: str, level: str) -> None:
    """Same version, same mask and same modules as the official client's encoder."""
    version, size, mask, expected = ZXING_GOLDEN[(name, level)]
    matrix = qr.encode(ZXING_PAYLOADS[name], ecc=level)
    assert (matrix.version, matrix.size, matrix.mask) == (version, size, mask)
    assert digest(matrix) == expected


def test_str_input_is_encoded_as_iso_8859_1() -> None:
    """Byte mode without an ECI designator presumes Latin-1, matching ZXing's default."""
    text = "Assinatura eletrônica — José"
    assert qr.encode(text).modules == qr.encode(ACCENTED_LATIN1).modules
    assert qr.encode("—").modules == qr.encode(b"?").modules  # unmappable becomes 0x3F
    assert qr.encode("\u00f4").modules == qr.encode(b"\xf4").modules
    assert qr.encode(text).modules != qr.encode(text.encode("utf-8")).modules


def test_matrix_accessors() -> None:
    matrix = qr.encode("oi")
    rows = matrix.rows()
    assert len(rows) == matrix.size
    assert all(len(row) == matrix.size for row in rows)
    assert [matrix.get(0, y) for y in range(matrix.size)] == [row[0] for row in rows]
    with pytest.raises(IndexError):
        matrix.get(matrix.size, 0)
    with pytest.raises(IndexError):
        matrix.get(-1, 0)

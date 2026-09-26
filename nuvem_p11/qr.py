"""QR Code generation in pure Python (ISO/IEC 18004).

Byte mode only, which is what the SerproID enrollment payload needs: a ``str`` is encoded
as ISO-8859-1 (the standard's presumption for byte mode without an ECI designator, and
ZXing's default), ``bytes`` are carried verbatim. The module covers the full standard:
versions 1..40 at every error-correction level, Reed-Solomon over GF(256), the module
matrix with all function patterns, mask selection by the four penalty rules, and
renderers to half-block text and to a hand-built PNG.

Standard library only -- no third-party QR/PIL dependency, no external binary.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

__all__ = ["Matrix", "encode", "to_text", "to_png"]

#: Error-correction levels, weakest to strongest.
ECC_LEVELS = ("L", "M", "Q", "H")

#: The 2-bit level field of the format information.
_ECC_BITS = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}

#: ``(ec codewords per block, ((blocks, data codewords per block), ...))`` per
#: version and level, from ISO/IEC 18004 table 9.
_RS_BLOCKS: dict[tuple[int, str], tuple[int, tuple[tuple[int, int], ...]]] = {
    (1, "L"): (7, ((1, 19),)),
    (1, "M"): (10, ((1, 16),)),
    (1, "Q"): (13, ((1, 13),)),
    (1, "H"): (17, ((1, 9),)),
    (2, "L"): (10, ((1, 34),)),
    (2, "M"): (16, ((1, 28),)),
    (2, "Q"): (22, ((1, 22),)),
    (2, "H"): (28, ((1, 16),)),
    (3, "L"): (15, ((1, 55),)),
    (3, "M"): (26, ((1, 44),)),
    (3, "Q"): (18, ((2, 17),)),
    (3, "H"): (22, ((2, 13),)),
    (4, "L"): (20, ((1, 80),)),
    (4, "M"): (18, ((2, 32),)),
    (4, "Q"): (26, ((2, 24),)),
    (4, "H"): (16, ((4, 9),)),
    (5, "L"): (26, ((1, 108),)),
    (5, "M"): (24, ((2, 43),)),
    (5, "Q"): (18, ((2, 15), (2, 16))),
    (5, "H"): (22, ((2, 11), (2, 12))),
    (6, "L"): (18, ((2, 68),)),
    (6, "M"): (16, ((4, 27),)),
    (6, "Q"): (24, ((4, 19),)),
    (6, "H"): (28, ((4, 15),)),
    (7, "L"): (20, ((2, 78),)),
    (7, "M"): (18, ((4, 31),)),
    (7, "Q"): (18, ((2, 14), (4, 15))),
    (7, "H"): (26, ((4, 13), (1, 14))),
    (8, "L"): (24, ((2, 97),)),
    (8, "M"): (22, ((2, 38), (2, 39))),
    (8, "Q"): (22, ((4, 18), (2, 19))),
    (8, "H"): (26, ((4, 14), (2, 15))),
    (9, "L"): (30, ((2, 116),)),
    (9, "M"): (22, ((3, 36), (2, 37))),
    (9, "Q"): (20, ((4, 16), (4, 17))),
    (9, "H"): (24, ((4, 12), (4, 13))),
    (10, "L"): (18, ((2, 68), (2, 69))),
    (10, "M"): (26, ((4, 43), (1, 44))),
    (10, "Q"): (24, ((6, 19), (2, 20))),
    (10, "H"): (28, ((6, 15), (2, 16))),
    (11, "L"): (20, ((4, 81),)),
    (11, "M"): (30, ((1, 50), (4, 51))),
    (11, "Q"): (28, ((4, 22), (4, 23))),
    (11, "H"): (24, ((3, 12), (8, 13))),
    (12, "L"): (24, ((2, 92), (2, 93))),
    (12, "M"): (22, ((6, 36), (2, 37))),
    (12, "Q"): (26, ((4, 20), (6, 21))),
    (12, "H"): (28, ((7, 14), (4, 15))),
    (13, "L"): (26, ((4, 107),)),
    (13, "M"): (22, ((8, 37), (1, 38))),
    (13, "Q"): (24, ((8, 20), (4, 21))),
    (13, "H"): (22, ((12, 11), (4, 12))),
    (14, "L"): (30, ((3, 115), (1, 116))),
    (14, "M"): (24, ((4, 40), (5, 41))),
    (14, "Q"): (20, ((11, 16), (5, 17))),
    (14, "H"): (24, ((11, 12), (5, 13))),
    (15, "L"): (22, ((5, 87), (1, 88))),
    (15, "M"): (24, ((5, 41), (5, 42))),
    (15, "Q"): (30, ((5, 24), (7, 25))),
    (15, "H"): (24, ((11, 12), (7, 13))),
    (16, "L"): (24, ((5, 98), (1, 99))),
    (16, "M"): (28, ((7, 45), (3, 46))),
    (16, "Q"): (24, ((15, 19), (2, 20))),
    (16, "H"): (30, ((3, 15), (13, 16))),
    (17, "L"): (28, ((1, 107), (5, 108))),
    (17, "M"): (28, ((10, 46), (1, 47))),
    (17, "Q"): (28, ((1, 22), (15, 23))),
    (17, "H"): (28, ((2, 14), (17, 15))),
    (18, "L"): (30, ((5, 120), (1, 121))),
    (18, "M"): (26, ((9, 43), (4, 44))),
    (18, "Q"): (28, ((17, 22), (1, 23))),
    (18, "H"): (28, ((2, 14), (19, 15))),
    (19, "L"): (28, ((3, 113), (4, 114))),
    (19, "M"): (26, ((3, 44), (11, 45))),
    (19, "Q"): (26, ((17, 21), (4, 22))),
    (19, "H"): (26, ((9, 13), (16, 14))),
    (20, "L"): (28, ((3, 107), (5, 108))),
    (20, "M"): (26, ((3, 41), (13, 42))),
    (20, "Q"): (30, ((15, 24), (5, 25))),
    (20, "H"): (28, ((15, 15), (10, 16))),
    (21, "L"): (28, ((4, 116), (4, 117))),
    (21, "M"): (26, ((17, 42),)),
    (21, "Q"): (28, ((17, 22), (6, 23))),
    (21, "H"): (30, ((19, 16), (6, 17))),
    (22, "L"): (28, ((2, 111), (7, 112))),
    (22, "M"): (28, ((17, 46),)),
    (22, "Q"): (30, ((7, 24), (16, 25))),
    (22, "H"): (24, ((34, 13),)),
    (23, "L"): (30, ((4, 121), (5, 122))),
    (23, "M"): (28, ((4, 47), (14, 48))),
    (23, "Q"): (30, ((11, 24), (14, 25))),
    (23, "H"): (30, ((16, 15), (14, 16))),
    (24, "L"): (30, ((6, 117), (4, 118))),
    (24, "M"): (28, ((6, 45), (14, 46))),
    (24, "Q"): (30, ((11, 24), (16, 25))),
    (24, "H"): (30, ((30, 16), (2, 17))),
    (25, "L"): (26, ((8, 106), (4, 107))),
    (25, "M"): (28, ((8, 47), (13, 48))),
    (25, "Q"): (30, ((7, 24), (22, 25))),
    (25, "H"): (30, ((22, 15), (13, 16))),
    (26, "L"): (28, ((10, 114), (2, 115))),
    (26, "M"): (28, ((19, 46), (4, 47))),
    (26, "Q"): (28, ((28, 22), (6, 23))),
    (26, "H"): (30, ((33, 16), (4, 17))),
    (27, "L"): (30, ((8, 122), (4, 123))),
    (27, "M"): (28, ((22, 45), (3, 46))),
    (27, "Q"): (30, ((8, 23), (26, 24))),
    (27, "H"): (30, ((12, 15), (28, 16))),
    (28, "L"): (30, ((3, 117), (10, 118))),
    (28, "M"): (28, ((3, 45), (23, 46))),
    (28, "Q"): (30, ((4, 24), (31, 25))),
    (28, "H"): (30, ((11, 15), (31, 16))),
    (29, "L"): (30, ((7, 116), (7, 117))),
    (29, "M"): (28, ((21, 45), (7, 46))),
    (29, "Q"): (30, ((1, 23), (37, 24))),
    (29, "H"): (30, ((19, 15), (26, 16))),
    (30, "L"): (30, ((5, 115), (10, 116))),
    (30, "M"): (28, ((19, 47), (10, 48))),
    (30, "Q"): (30, ((15, 24), (25, 25))),
    (30, "H"): (30, ((23, 15), (25, 16))),
    (31, "L"): (30, ((13, 115), (3, 116))),
    (31, "M"): (28, ((2, 46), (29, 47))),
    (31, "Q"): (30, ((42, 24), (1, 25))),
    (31, "H"): (30, ((23, 15), (28, 16))),
    (32, "L"): (30, ((17, 115),)),
    (32, "M"): (28, ((10, 46), (23, 47))),
    (32, "Q"): (30, ((10, 24), (35, 25))),
    (32, "H"): (30, ((19, 15), (35, 16))),
    (33, "L"): (30, ((17, 115), (1, 116))),
    (33, "M"): (28, ((14, 46), (21, 47))),
    (33, "Q"): (30, ((29, 24), (19, 25))),
    (33, "H"): (30, ((11, 15), (46, 16))),
    (34, "L"): (30, ((13, 115), (6, 116))),
    (34, "M"): (28, ((14, 46), (23, 47))),
    (34, "Q"): (30, ((44, 24), (7, 25))),
    (34, "H"): (30, ((59, 16), (1, 17))),
    (35, "L"): (30, ((12, 121), (7, 122))),
    (35, "M"): (28, ((12, 47), (26, 48))),
    (35, "Q"): (30, ((39, 24), (14, 25))),
    (35, "H"): (30, ((22, 15), (41, 16))),
    (36, "L"): (30, ((6, 121), (14, 122))),
    (36, "M"): (28, ((6, 47), (34, 48))),
    (36, "Q"): (30, ((46, 24), (10, 25))),
    (36, "H"): (30, ((2, 15), (64, 16))),
    (37, "L"): (30, ((17, 122), (4, 123))),
    (37, "M"): (28, ((29, 46), (14, 47))),
    (37, "Q"): (30, ((49, 24), (10, 25))),
    (37, "H"): (30, ((24, 15), (46, 16))),
    (38, "L"): (30, ((4, 122), (18, 123))),
    (38, "M"): (28, ((13, 46), (32, 47))),
    (38, "Q"): (30, ((48, 24), (14, 25))),
    (38, "H"): (30, ((42, 15), (32, 16))),
    (39, "L"): (30, ((20, 117), (4, 118))),
    (39, "M"): (28, ((40, 47), (7, 48))),
    (39, "Q"): (30, ((43, 24), (22, 25))),
    (39, "H"): (30, ((10, 15), (67, 16))),
    (40, "L"): (30, ((19, 118), (6, 119))),
    (40, "M"): (28, ((18, 47), (31, 48))),
    (40, "Q"): (30, ((34, 24), (34, 25))),
    (40, "H"): (30, ((20, 15), (61, 16))),
}

#: Alignment pattern centre coordinates per version (ISO/IEC 18004 annex E).
_ALIGNMENT_CENTRES: tuple[tuple[int, ...], ...] = (
    (),
    (6, 18),
    (6, 22),
    (6, 26),
    (6, 30),
    (6, 34),
    (6, 22, 38),
    (6, 24, 42),
    (6, 26, 46),
    (6, 28, 50),
    (6, 30, 54),
    (6, 32, 58),
    (6, 34, 62),
    (6, 26, 46, 66),
    (6, 26, 48, 70),
    (6, 26, 50, 74),
    (6, 30, 54, 78),
    (6, 30, 56, 82),
    (6, 30, 58, 86),
    (6, 34, 62, 90),
    (6, 28, 50, 72, 94),
    (6, 26, 50, 74, 98),
    (6, 30, 54, 78, 102),
    (6, 28, 54, 80, 106),
    (6, 32, 58, 84, 110),
    (6, 30, 58, 86, 114),
    (6, 34, 62, 90, 118),
    (6, 26, 50, 74, 98, 122),
    (6, 30, 54, 78, 102, 126),
    (6, 26, 52, 78, 104, 130),
    (6, 30, 56, 82, 108, 134),
    (6, 34, 60, 86, 112, 138),
    (6, 30, 58, 86, 114, 142),
    (6, 34, 62, 90, 118, 146),
    (6, 30, 54, 78, 102, 126, 150),
    (6, 24, 50, 76, 102, 128, 154),
    (6, 28, 54, 80, 106, 132, 158),
    (6, 32, 58, 84, 110, 136, 162),
    (6, 26, 54, 82, 110, 138, 166),
    (6, 30, 58, 86, 114, 142, 170),
)


# --- GF(256), primitive polynomial 0x11D, generator alpha = 2 -------------------

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_value = 1
for _i in range(255):
    _GF_EXP[_i] = _value
    _GF_LOG[_value] = _i
    _value <<= 1
    if _value & 0x100:
        _value ^= 0x11D
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]
del _i, _value


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(degree: int) -> list[int]:
    """Product of ``(x - alpha**i)`` for ``i`` in ``0..degree-1``."""
    generator = [1]
    for i in range(degree):
        factor = [1, _GF_EXP[i]]
        product = [0] * (len(generator) + 1)
        for a, av in enumerate(generator):
            if av:
                product[a] ^= av
                product[a + 1] ^= _gf_mul(av, factor[1])
        generator = product
    return generator


def _rs_encode(data: list[int], degree: int) -> list[int]:
    """EC codewords: the remainder of ``data * x**degree`` by the generator."""
    generator = _rs_generator(degree)
    remainder = [0] * degree
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        if factor:
            for i in range(degree):
                remainder[i] ^= _gf_mul(generator[i + 1], factor)
    return remainder


# --- bit-level helpers -----------------------------------------------------------


def _bch_remainder(value: int, generator: int, degree: int) -> int:
    """Polynomial remainder of ``value`` divided by ``generator`` over GF(2)."""
    while value.bit_length() > degree:
        value ^= generator << (value.bit_length() - degree - 1)
    return value


def _format_bits(ecc: str, mask: int) -> int:
    """15-bit format information: 5 data bits, BCH(15,5), XOR 0x5412."""
    data = (_ECC_BITS[ecc] << 3) | mask
    return ((data << 10) | _bch_remainder(data << 10, 0x537, 10)) ^ 0x5412


def _version_bits(version: int) -> int:
    """18-bit version information: 6 data bits plus BCH(18,6), generator 0x1F25."""
    return (version << 12) | _bch_remainder(version << 12, 0x1F25, 12)


# --- matrix ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Matrix:
    """A finished QR symbol: ``size`` is the side in modules, boundary included."""

    size: int
    version: int
    ecc: str
    mask: int
    modules: tuple[tuple[bool, ...], ...]

    def get(self, x: int, y: int) -> bool:
        """Whether the module at column ``x``, row ``y`` is dark."""
        if not 0 <= x < self.size or not 0 <= y < self.size:
            raise IndexError(f"module ({x}, {y}) outside the {self.size}x{self.size} matrix")
        return self.modules[y][x]

    def rows(self) -> list[list[bool]]:
        """The module grid as mutable rows, top to bottom."""
        return [list(row) for row in self.modules]


class _Canvas:
    """Module grid under construction; ``function`` marks reserved modules."""

    def __init__(self, version: int) -> None:
        self.version = version
        self.size = 4 * version + 17
        self.modules = [[False] * self.size for _ in range(self.size)]
        self.function = [[False] * self.size for _ in range(self.size)]

    def set(self, x: int, y: int, dark: bool, *, function: bool = False) -> None:
        if 0 <= x < self.size and 0 <= y < self.size:
            self.modules[y][x] = dark
            if function:
                self.function[y][x] = True


def _draw_finders(canvas: _Canvas) -> None:
    """The three 7x7 finder patterns plus their one-module separators."""
    last = canvas.size - 7
    for ox, oy in ((0, 0), (last, 0), (0, last)):
        for dy in range(-1, 8):
            for dx in range(-1, 8):
                if not (0 <= ox + dx < canvas.size and 0 <= oy + dy < canvas.size):
                    continue
                inside = 0 <= dx <= 6 and 0 <= dy <= 6
                dark = inside and (
                    dx in (0, 6) or dy in (0, 6) or (2 <= dx <= 4 and 2 <= dy <= 4)
                )
                canvas.set(ox + dx, oy + dy, dark, function=True)


def _draw_timing(canvas: _Canvas) -> None:
    """Alternating row/column 6 between the finder patterns."""
    for i in range(8, canvas.size - 8):
        dark = i % 2 == 0
        canvas.set(i, 6, dark, function=True)
        canvas.set(6, i, dark, function=True)


def _draw_alignment(canvas: _Canvas) -> None:
    """5x5 alignment patterns, minus the three that would overlap a finder."""
    centres = _ALIGNMENT_CENTRES[canvas.version - 1]
    last = canvas.size - 7
    for cy in centres:
        for cx in centres:
            if (cx <= 8 and cy <= 8) or (cx >= last and cy <= 8) or (cx <= 8 and cy >= last):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    dark = max(abs(dx), abs(dy)) != 1
                    canvas.set(cx + dx, cy + dy, dark, function=True)


def _draw_dark_module(canvas: _Canvas) -> None:
    """The always-dark module above the bottom-left format information."""
    canvas.set(8, canvas.size - 8, True, function=True)


def _format_coords() -> list[tuple[int, int]]:
    """Module positions of the format information, least significant bit first.

    Row and column 8 both skip index 6, which belongs to the timing patterns.
    """
    coords = [(8, i) for i in range(6)]
    coords += [(8, 7), (8, 8), (7, 8)]
    return coords + [(14 - i, 8) for i in range(9, 15)]


def _format_coords_second(size: int) -> list[tuple[int, int]]:
    """Positions of the second, split copy of the format information."""
    return [(size - 1 - i, 8) for i in range(8)] + [(8, size - 15 + i) for i in range(8, 15)]


def _reserve_format(canvas: _Canvas) -> None:
    """Reserve both copies of the format information."""
    for x, y in _format_coords() + _format_coords_second(canvas.size):
        canvas.set(x, y, False, function=True)


def _reserve_version(canvas: _Canvas) -> None:
    """Reserve the two 6x3 version information blocks (version 7 and up)."""
    if canvas.version < 7:
        return
    size = canvas.size
    for i in range(18):
        a = size - 11 + i % 3
        b = i // 3
        canvas.set(a, b, False, function=True)
        canvas.set(b, a, False, function=True)


def _data_module_count(version: int) -> int:
    """Modules available to data and EC codewords, before masking."""
    canvas = _Canvas(version)
    _draw_finders(canvas)
    _draw_timing(canvas)
    _draw_alignment(canvas)
    _draw_dark_module(canvas)
    _reserve_format(canvas)
    _reserve_version(canvas)
    return sum(not f for row in canvas.function for f in row)


def _place_data(canvas: _Canvas, bits: list[int]) -> None:
    """Zig-zag codeword placement from the bottom-right corner, column 6 skipped."""
    size = canvas.size
    index = 0
    column = size - 1
    upward = True
    while column > 0:
        if column == 6:
            column -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for y in rows:
            for x in (column, column - 1):
                if canvas.function[y][x]:
                    continue
                canvas.modules[y][x] = bits[index] == 1 if index < len(bits) else False
                index += 1
        column -= 2
        upward = not upward


def _mask_bit(mask: int, x: int, y: int) -> bool:
    if mask == 0:
        return (x + y) % 2 == 0
    if mask == 1:
        return y % 2 == 0
    if mask == 2:
        return x % 3 == 0
    if mask == 3:
        return (x + y) % 3 == 0
    if mask == 4:
        return (y // 2 + x // 3) % 2 == 0
    if mask == 5:
        return (x * y) % 2 + (x * y) % 3 == 0
    if mask == 6:
        return ((x * y) % 2 + (x * y) % 3) % 2 == 0
    return ((x + y) % 2 + (x * y) % 3) % 2 == 0


def _apply_mask(canvas: _Canvas, mask: int) -> None:
    for y in range(canvas.size):
        for x in range(canvas.size):
            if not canvas.function[y][x] and _mask_bit(mask, x, y):
                canvas.modules[y][x] = not canvas.modules[y][x]


def _draw_format(canvas: _Canvas, ecc: str, mask: int) -> None:
    """Both copies of the format information."""
    bits = _format_bits(ecc, mask)
    for bit, (x, y) in enumerate(_format_coords()):
        canvas.set(x, y, (bits >> bit) & 1 == 1, function=True)
    for bit, (x, y) in enumerate(_format_coords_second(canvas.size)):
        canvas.set(x, y, (bits >> bit) & 1 == 1, function=True)


def _draw_version(canvas: _Canvas) -> None:
    if canvas.version < 7:
        return
    bits = _version_bits(canvas.version)
    size = canvas.size
    for i in range(18):
        dark = (bits >> i) & 1 == 1
        a = size - 11 + i % 3
        b = i // 3
        canvas.set(a, b, dark, function=True)
        canvas.set(b, a, dark, function=True)


# --- mask selection --------------------------------------------------------------


#: The 1:1:3:1:1 module run of the finder patterns, as tested by penalty rule 3.
_FINDER_LIKE = (True, False, True, True, True, False, True)


def _is_finder_like(line: list[bool], index: int) -> bool:
    return all(line[index + i] == want for i, want in enumerate(_FINDER_LIKE))


def _all_light(line: list[bool], start: int, stop: int) -> bool:
    """Whether ``line[start:stop]`` is entirely light, clamped to the line's bounds."""
    return not any(line[max(start, 0) : min(stop, len(line))])


def _penalty(modules: list[list[bool]]) -> int:
    """Total penalty of the four ISO/IEC 18004 mask evaluation rules."""
    size = len(modules)
    score = 0

    # Rule 1: runs of five or more modules of one colour, in rows and columns.
    for lines in (modules, [[modules[y][x] for y in range(size)] for x in range(size)]):
        for line in lines:
            run = 1
            for i in range(1, size):
                if line[i] == line[i - 1]:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + run - 5
                    run = 1
            if run >= 5:
                score += 3 + run - 5

    # Rule 2: every 2x2 block of one colour.
    for y in range(size - 1):
        for x in range(size - 1):
            if modules[y][x] == modules[y][x + 1] == modules[y + 1][x] == modules[y + 1][x + 1]:
                score += 3

    # Rule 3: the finder-like 1:1:3:1:1 pattern with four light modules on a side.
    # Evaluated the way ZXing does it (the encoder of the reference client): the light
    # run is clamped at the symbol border, and a pattern counts once even when both
    # sides are light.
    for y in range(size):
        row = modules[y]
        for x in range(size - 6):
            if _is_finder_like(row, x) and (
                _all_light(row, x - 4, x) or _all_light(row, x + 7, x + 11)
            ):
                score += 40
    for x in range(size):
        column = [modules[y][x] for y in range(size)]
        for y in range(size - 6):
            if _is_finder_like(column, y) and (
                _all_light(column, y - 4, y) or _all_light(column, y + 7, y + 11)
            ):
                score += 40

    # Rule 4: deviation of the dark module ratio from 50%, in 5% steps.
    dark = sum(sum(row) for row in modules)
    score += abs(dark * 20 - size * size * 10) // (size * size) * 10
    return score


# --- public API ------------------------------------------------------------------


def _payload_bytes(data: bytes | str) -> bytes:
    """Byte-mode content: ``bytes`` verbatim, ``str`` as Latin-1.

    Byte mode carries no ECI designator, so ISO/IEC 18004 presumes ISO-8859-1. That is
    also the charset ZXing's ``Encoder`` uses by default -- the encoder inside the
    official client -- and Java's ``String.getBytes(ISO_8859_1)`` maps anything outside
    Latin-1 to ``?``, which is what Python's ``replace`` handler emits too.
    """
    if isinstance(data, bytes):
        return bytes(data)
    return data.encode("iso-8859-1", errors="replace")


def encode(data: bytes | str, *, ecc: str = "M", min_version: int = 1) -> Matrix:
    """Encode ``data`` in byte mode, picking the smallest version that fits.

    A ``str`` is encoded as ISO-8859-1, the standard's presumption for byte mode without
    an ECI designator (characters outside Latin-1 become ``?``); pass ``bytes`` to carry
    any other encoding verbatim. ``ecc`` is one of L/M/Q/H; ``min_version`` forces a
    larger symbol than strictly needed. Raises ``ValueError`` for an unknown level, an
    out-of-range version, or data that does not fit the largest symbol at that level.
    """
    payload = _payload_bytes(data)
    level = ecc.upper()
    if level not in _ECC_BITS:
        raise ValueError(f"unknown error correction level {ecc!r}, expected one of {ECC_LEVELS}")
    if not 1 <= min_version <= 40:
        raise ValueError(f"min_version must be between 1 and 40, got {min_version}")

    version = _pick_version(len(payload), level, min_version)
    codewords = _interleave(_data_codewords(payload, version, level), version, level)

    best: Matrix | None = None
    best_score = -1
    for mask in range(8):
        matrix = _render(version, level, codewords, mask)
        score = _penalty(matrix.rows())
        if best is None or score < best_score:
            best, best_score = matrix, score
    assert best is not None
    return best


def _pick_version(length: int, level: str, min_version: int) -> int:
    for version in range(min_version, 41):
        data_codewords = sum(count * size for count, size in _RS_BLOCKS[(version, level)][1])
        count_bits = 8 if version < 10 else 16
        if 4 + count_bits + 8 * length <= 8 * data_codewords:
            return version
    raise ValueError(
        f"{length} bytes do not fit any version up to 40 at level {level} "
        f"(maximum {sum(c * s for c, s in _RS_BLOCKS[(40, level)][1]) - 3} bytes)"
    )


def _data_codewords(payload: bytes, version: int, level: str) -> list[int]:
    """Mode indicator, character count, payload, terminator and pad codewords."""
    capacity = sum(count * size for count, size in _RS_BLOCKS[(version, level)][1])
    count_bits = 8 if version < 10 else 16

    bits: list[int] = [0, 1, 0, 0]  # byte mode
    bits += [(len(payload) >> i) & 1 for i in range(count_bits - 1, -1, -1)]
    for byte in payload:
        bits += [(byte >> i) & 1 for i in range(7, -1, -1)]

    bits += [0] * min(4, capacity * 8 - len(bits))  # terminator
    bits += [0] * (-len(bits) % 8)  # byte alignment
    codewords = [int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits), 8)]
    for i in range(capacity - len(codewords)):
        codewords.append(0xEC if i % 2 == 0 else 0x11)
    return codewords


def _interleave(data: list[int], version: int, level: str) -> list[int]:
    """Split into RS blocks, add EC codewords, then interleave both sequences."""
    ec_per_block, structure = _RS_BLOCKS[(version, level)]
    blocks: list[list[int]] = []
    ec_blocks: list[list[int]] = []
    offset = 0
    for count, size in structure:
        for _ in range(count):
            block = data[offset : offset + size]
            offset += size
            blocks.append(block)
            ec_blocks.append(_rs_encode(block, ec_per_block))

    result: list[int] = []
    for i in range(max(len(block) for block in blocks)):
        for block in blocks:
            if i < len(block):
                result.append(block[i])
    for i in range(ec_per_block):
        for block in ec_blocks:
            result.append(block[i])
    return result


def _render(version: int, level: str, codewords: list[int], mask: int) -> Matrix:
    canvas = _Canvas(version)
    _draw_finders(canvas)
    _draw_timing(canvas)
    _draw_alignment(canvas)
    _draw_dark_module(canvas)
    _reserve_format(canvas)
    _reserve_version(canvas)

    bits = [(byte >> i) & 1 for byte in codewords for i in range(7, -1, -1)]
    _place_data(canvas, bits)
    _apply_mask(canvas, mask)
    _draw_format(canvas, level, mask)
    _draw_version(canvas)

    return Matrix(
        size=canvas.size,
        version=version,
        ecc=level,
        mask=mask,
        modules=tuple(tuple(row) for row in canvas.modules),
    )


# --- rendering -------------------------------------------------------------------

#: Full, upper-half, lower-half and blank glyphs, one module column wide each.
_TEXT_GLYPHS = "\u2588\u2580\u2584 "


def to_text(matrix: Matrix, *, quiet: int = 4, light: str | None = None) -> str:
    """Render as half-block text: one text line covers two module rows.

    ``light`` overrides the four glyphs (both dark, upper dark, lower dark, both light)
    when a caller needs different metrics; the default is one column per module.
    """
    glyphs = _TEXT_GLYPHS if light is None else light
    if len(glyphs) != 4:
        raise ValueError(f"light must provide exactly 4 characters, got {len(glyphs)}")

    span = matrix.size + 2 * quiet
    lines: list[str] = []
    for top in range(0, span, 2):
        y0 = top - quiet
        y1 = top + 1 - quiet
        line = []
        for x in range(-quiet, matrix.size + quiet):
            upper = 0 <= y0 < matrix.size and 0 <= x < matrix.size and matrix.modules[y0][x]
            lower = 0 <= y1 < matrix.size and 0 <= x < matrix.size and matrix.modules[y1][x]
            if upper and lower:
                line.append(glyphs[0])
            elif upper:
                line.append(glyphs[1])
            elif lower:
                line.append(glyphs[2])
            else:
                line.append(glyphs[3])
        lines.append("".join(line))
    return "\n".join(lines) + "\n"


def _chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def to_png(matrix: Matrix, *, scale: int = 8, quiet: int = 4) -> bytes:
    """Render as an 8-bit greyscale PNG, one pixel per module times ``scale``.

    Nothing in the utility renders images -- the terminal output is the only way it shows a
    symbol. This exists so the tests can hand the symbol to an *independent* decoder
    (``zbarimg``) and prove it really scans; without an image file there is no way to check
    that. Keep it for that reason, not for display.
    """
    if scale < 1:
        raise ValueError(f"scale must be positive, got {scale}")
    if quiet < 0:
        raise ValueError(f"quiet must not be negative, got {quiet}")

    size = matrix.size
    side = (size + 2 * quiet) * scale
    white = bytes([0xFF]) * side
    raw = bytearray()
    for py in range(side):
        my = py // scale - quiet
        if 0 <= my < size:
            row = bytearray(white)
            for mx in range(size):
                if matrix.modules[my][mx]:
                    start = (mx + quiet) * scale
                    row[start : start + scale] = b"\x00" * scale
            line = bytes(row)
        else:
            line = white
        raw += b"\x00" + line  # per-scanline filter type: none

    header = struct.pack(">IIBBBBB", side, side, 8, 0, 0, 0, 0)  # greyscale, no interlace
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _chunk(b"IEND", b"")
    )

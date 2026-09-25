# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""BER (ITU-T X.690) primitives.

Tags are handled as the integer value of their identifier octets, so a
one-byte tag reads naturally (``0x83``, ``0xA2``) and a high-tag-number form
such as ``[APPLICATION 72]`` is ``0x7F48``. Only definite lengths are
supported: IEC 61850 never uses the indefinite form.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import NamedTuple


class BerError(ValueError):
    """Malformed or truncated BER data."""


class Tlv(NamedTuple):
    """One decoded TLV: tag, content octets and the offset right after it."""

    tag: int
    value: bytes
    end: int


# --- tags --------------------------------------------------------------------

CLASS_UNIVERSAL = 0x00
CLASS_APPLICATION = 0x40
CLASS_CONTEXT = 0x80
CLASS_PRIVATE = 0xC0
CONSTRUCTED = 0x20


def make_tag(number: int, cls: int = CLASS_CONTEXT, constructed: bool = False) -> int:
    """Build a tag from its class, form and number (any number, low or high form)."""
    if number < 0:
        raise ValueError("tag number must be non-negative")
    first = cls | (CONSTRUCTED if constructed else 0)
    if number < 0x1F:
        return first | number
    groups = []
    n = number
    while True:
        groups.append(n & 0x7F)
        n >>= 7
        if not n:
            break
    octets = [first | 0x1F]
    for i, g in enumerate(reversed(groups)):
        octets.append(g | (0x80 if i < len(groups) - 1 else 0))
    return int.from_bytes(bytes(octets), "big")


def tag_number(tag: int) -> int:
    """Tag number without the class and form bits."""
    raw = tag.to_bytes(max(1, (tag.bit_length() + 7) // 8), "big")
    if raw[0] & 0x1F != 0x1F:
        return raw[0] & 0x1F
    n = 0
    for b in raw[1:]:
        n = (n << 7) | (b & 0x7F)
    return n


def is_constructed(tag: int) -> bool:
    raw = tag.to_bytes(max(1, (tag.bit_length() + 7) // 8), "big")
    return bool(raw[0] & CONSTRUCTED)


def encode_tag(tag: int) -> bytes:
    return tag.to_bytes(max(1, (tag.bit_length() + 7) // 8), "big")


def decode_tag(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return ``(tag, next_offset)``."""
    if offset >= len(data):
        raise BerError("missing tag")
    first = data[offset]
    offset += 1
    tag = first
    if first & 0x1F == 0x1F:
        while True:
            if offset >= len(data):
                raise BerError("truncated high-number tag")
            b = data[offset]
            offset += 1
            tag = (tag << 8) | b
            if not b & 0x80:
                break
    return tag, offset


# --- lengths -----------------------------------------------------------------


def encode_length(length: int) -> bytes:
    """Definite length, short form below 128, minimal long form otherwise."""
    if length < 0:
        raise ValueError("length must be non-negative")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(raw) > 0x7E:
        raise ValueError("length too large")
    return bytes([0x80 | len(raw)]) + raw


def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return ``(length, next_offset)``."""
    if offset >= len(data):
        raise BerError("missing length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    n = first & 0x7F
    if n == 0:
        raise BerError("indefinite length is not supported")
    if offset + n > len(data):
        raise BerError("truncated long-form length")
    return int.from_bytes(data[offset : offset + n], "big"), offset + n


# --- TLV ---------------------------------------------------------------------


def encode_tlv(tag: int, content: bytes = b"") -> bytes:
    return encode_tag(tag) + encode_length(len(content)) + bytes(content)


def decode_tlv(data: bytes, offset: int = 0) -> Tlv:
    # Fast path for a low tag number and a short length, the usual case on the
    # process bus (SV decoding runs thousands of times per second).
    if offset + 2 <= len(data) and data[offset] & 0x1F != 0x1F and data[offset + 1] < 0x80:
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
    else:
        tag, offset = decode_tag(data, offset)
        length, offset = decode_length(data, offset)
    end = offset + length
    if end > len(data):
        raise BerError(f"TLV 0x{tag:X} truncated: needs {length} bytes, {len(data) - offset} left")
    return Tlv(tag, bytes(data[offset:end]), end)


def iter_tlvs(data: bytes) -> Iterator[Tlv]:
    """Iterate over consecutive TLVs covering exactly ``data``."""
    offset = 0
    while offset < len(data):
        tlv = decode_tlv(data, offset)
        yield tlv
        offset = tlv.end


def expect_tlv(data: bytes, offset: int, tag: int) -> Tlv:
    """Decode a TLV and check its tag."""
    tlv = decode_tlv(data, offset)
    if tlv.tag != tag:
        raise BerError(f"expected tag 0x{tag:X} at offset {offset}, found 0x{tlv.tag:X}")
    return tlv


# --- INTEGER -----------------------------------------------------------------


def encode_integer(value: int) -> bytes:
    """Minimal two's-complement content octets of an INTEGER (X.690 8.3)."""
    length = max(1, (value + (value < 0)).bit_length() // 8 + 1)
    return value.to_bytes(length, "big", signed=True)


def encode_unsigned(value: int) -> bytes:
    """Content octets of a non-negative INTEGER (a leading 0x00 keeps it positive)."""
    if value < 0:
        raise ValueError("unsigned value must be non-negative")
    return encode_integer(value)


def decode_integer(content: bytes) -> int:
    if not content:
        raise BerError("empty INTEGER")
    return int.from_bytes(content, "big", signed=True)


def decode_unsigned(content: bytes) -> int:
    """Lenient decoding for unsigned fields.

    Accepts the conformant form (leading 0x00 when the high bit is set) and
    the common non-conformant one without it.
    """
    if not content:
        raise BerError("empty INTEGER")
    return int.from_bytes(content, "big")


# --- BOOLEAN -----------------------------------------------------------------


def encode_boolean(value: bool) -> bytes:
    return b"\xff" if value else b"\x00"


def decode_boolean(content: bytes) -> bool:
    if len(content) != 1:
        raise BerError(f"BOOLEAN must be one byte, got {len(content)}")
    return content[0] != 0


# --- OBJECT IDENTIFIER -------------------------------------------------------


def encode_oid(arcs: tuple[int, ...]) -> bytes:
    """Content octets of an OBJECT IDENTIFIER (X.690 8.19)."""
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39) or min(arcs) < 0:
        raise ValueError(f"invalid object identifier {arcs}")
    out = bytearray()
    for arc in (arcs[0] * 40 + arcs[1], *arcs[2:]):
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


def decode_oid(content: bytes) -> tuple[int, ...]:
    if not content or content[-1] & 0x80:
        raise BerError(f"bad OBJECT IDENTIFIER {content.hex()}")
    values, arc = [], 0
    for byte in content:
        arc = (arc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(arc)
            arc = 0
    first = min(values[0] // 40, 2)
    return (first, values[0] - 40 * first, *values[1:])

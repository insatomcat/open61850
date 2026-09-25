# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The MMS ``Data`` CHOICE (ISO 9506-2, profiled by IEC 61850-8-1).

It is the value model of MMS reads, writes and reports, and of GOOSE
``allData``. Context tags::

    [1]  0xA1  array          [9]  0x89  octet-string
    [2]  0xA2  structure      [10] 0x8A  visible-string
    [3]  0x83  boolean        [12] 0x8C  binary-time
    [4]  0x84  bit-string     [15] 0x8F  mms-string (UTF-8)
    [5]  0x85  integer        [17] 0x91  utc-time
    [6]  0x86  unsigned
    [7]  0x87  floating-point

Decoding is lenient where field devices are known to deviate (unsigned
values without their leading zero, booleans longer than one byte); values of
an unknown tag or an unexpected size are kept as :class:`RawData`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Union

from . import ber

__all__ = [
    "TAG_ARRAY",
    "TAG_STRUCTURE",
    "TAG_BOOLEAN",
    "TAG_BIT_STRING",
    "TAG_INTEGER",
    "TAG_UNSIGNED",
    "TAG_FLOAT",
    "TAG_OCTET_STRING",
    "TAG_VISIBLE_STRING",
    "TAG_BINARY_TIME",
    "TAG_MMS_STRING",
    "TAG_UTC_TIME",
    "BoolData",
    "IntData",
    "UIntData",
    "FloatData",
    "BitStringData",
    "OctetStringData",
    "VisibleStringData",
    "MmsStringData",
    "TimestampData",
    "StructureData",
    "ArrayData",
    "RawData",
    "IECData",
    "DATA_TYPES",
    "encode_utc_time",
    "decode_utc_time",
    "encode_binary_time",
    "decode_binary_time",
    "decode_data",
    "decode_data_at",
    "decode_data_sequence",
    "encode_data",
]


TAG_ARRAY = 0xA1
TAG_STRUCTURE = 0xA2
TAG_BOOLEAN = 0x83
TAG_BIT_STRING = 0x84
TAG_INTEGER = 0x85
TAG_UNSIGNED = 0x86
TAG_FLOAT = 0x87
TAG_OCTET_STRING = 0x89
TAG_VISIBLE_STRING = 0x8A
TAG_BINARY_TIME = 0x8C
TAG_MMS_STRING = 0x8F
TAG_UTC_TIME = 0x91

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_EPOCH_1984 = datetime(1984, 1, 1, tzinfo=timezone.utc)
_FLOAT32_FORMAT = 0x08  # IEEE 754 single: 8 exponent bits
_FLOAT64_FORMAT = 0x0B  # IEEE 754 double: 11 exponent bits


@dataclass
class BoolData:
    value: bool

    def __repr__(self) -> str:
        return f"bool({self.value})"


@dataclass
class IntData:
    value: int

    def __repr__(self) -> str:
        return f"int({self.value})"


@dataclass
class UIntData:
    value: int

    def __repr__(self) -> str:
        return f"uint({self.value})"


@dataclass
class FloatData:
    value: float
    double: bool = False

    def __repr__(self) -> str:
        return f"float{64 if self.double else 32}({self.value})"


@dataclass
class BitStringData:
    """Bits packed MSB first; ``unused_bits`` trailing bits of the last byte are padding."""

    value: bytes
    unused_bits: int = 0

    def __repr__(self) -> str:
        return f"bit-string({self.value.hex()}, unused={self.unused_bits})"


@dataclass
class OctetStringData:
    value: bytes

    def __repr__(self) -> str:
        return f"octet-string({self.value.hex()})"


@dataclass
class VisibleStringData:
    value: str

    def __repr__(self) -> str:
        return f"visible-string({self.value!r})"


@dataclass
class MmsStringData:
    value: str

    def __repr__(self) -> str:
        return f"mms-string({self.value!r})"


@dataclass
class TimestampData:
    """A utc-time or binary-time value.

    ``quality`` is the TimeQuality octet of a utc-time (leap seconds known,
    clock failure, clock not synchronized, 5-bit accuracy).
    """

    value: datetime
    quality: int = 0

    def __repr__(self) -> str:
        q = f", q=0x{self.quality:02x}" if self.quality else ""
        return f"timestamp({self.value.isoformat()}{q})"


@dataclass
class StructureData:
    members: list[IECData] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"structure({self.members!r})"


@dataclass
class ArrayData:
    elements: list[IECData] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"array({self.elements!r})"


@dataclass
class RawData:
    """A value kept as its raw tag and content octets."""

    tag: int
    value: bytes

    def __repr__(self) -> str:
        return f"raw(tag=0x{self.tag:02X}, {self.value.hex()})"


IECData = Union[
    BoolData, IntData, UIntData, FloatData,
    BitStringData, OctetStringData, VisibleStringData, MmsStringData,
    TimestampData, StructureData, ArrayData, RawData,
]

DATA_TYPES = (
    BoolData, IntData, UIntData, FloatData,
    BitStringData, OctetStringData, VisibleStringData, MmsStringData,
    TimestampData, StructureData, ArrayData, RawData,
)


# --- time encodings ----------------------------------------------------------


def encode_utc_time(value: datetime, quality: int = 0) -> bytes:
    """8-octet UtcTime: seconds (4), fraction of second in 2^-24 units (3), quality (1)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = value - _EPOCH
    secs = delta.days * 86400 + delta.seconds
    frac = (delta.microseconds * (1 << 24) + 500_000) // 1_000_000
    if frac > 0xFFFFFF:
        frac = 0xFFFFFF
    return secs.to_bytes(4, "big") + frac.to_bytes(3, "big") + bytes([quality & 0xFF])


def decode_utc_time(raw: bytes) -> tuple[datetime, int]:
    """Return ``(datetime, quality)`` from an 8-octet UtcTime."""
    if len(raw) < 8:
        raise ber.BerError(f"utc-time needs 8 bytes, got {len(raw)}")
    secs = int.from_bytes(raw[0:4], "big")
    frac = int.from_bytes(raw[4:7], "big")
    micros = (frac * 1_000_000 + (1 << 23)) >> 24
    return _EPOCH + timedelta(seconds=secs, microseconds=micros), raw[7]


def encode_binary_time(value: datetime) -> bytes:
    """6-octet TimeOfDay: milliseconds since midnight (4), days since 1984-01-01 (2)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = value - _EPOCH_1984
    ms = delta.seconds * 1000 + delta.microseconds // 1000
    return ms.to_bytes(4, "big") + delta.days.to_bytes(2, "big")


def decode_binary_time(raw: bytes) -> datetime:
    if len(raw) != 6:
        raise ber.BerError(f"binary-time with date needs 6 bytes, got {len(raw)}")
    ms = int.from_bytes(raw[0:4], "big")
    days = int.from_bytes(raw[4:6], "big")
    return _EPOCH_1984 + timedelta(days=days, milliseconds=ms)


def _shortest_float32(raw: bytes) -> float:
    """Shortest decimal that maps back to the same float32 (1.1, not 1.100000023841858)."""
    exact = struct.unpack("!f", raw)[0]
    if exact != exact or exact in (float("inf"), float("-inf")):
        return exact
    for digits in range(1, 10):
        candidate = float(f"{exact:.{digits}g}")
        if struct.pack("!f", candidate) == raw:
            return candidate
    return exact


# --- decoding ----------------------------------------------------------------


def decode_data(tag: int, value: bytes) -> IECData:
    """Decode one ``Data`` value from its tag and content octets."""
    if tag == TAG_BOOLEAN:
        return BoolData(bool(value) and value[0] != 0)
    if tag == TAG_BIT_STRING:
        unused = value[0] if value else 0
        return BitStringData(bytes(value[1:]), unused)
    if tag == TAG_INTEGER:
        return IntData(int.from_bytes(value, "big", signed=True) if value else 0)
    if tag == TAG_UNSIGNED:
        return UIntData(int.from_bytes(value, "big") if value else 0)
    if tag == TAG_FLOAT:
        if len(value) == 5:
            return FloatData(_shortest_float32(value[1:]))
        if len(value) == 9:
            return FloatData(struct.unpack("!d", value[1:])[0], double=True)
    if tag == TAG_OCTET_STRING:
        return OctetStringData(bytes(value))
    if tag in (TAG_VISIBLE_STRING, 0x1A, 0x80):  # IA5/VisibleString variants seen in the field
        return VisibleStringData(value.decode("ascii", errors="replace"))
    if tag == TAG_BINARY_TIME and len(value) == 6:
        return TimestampData(decode_binary_time(value))
    if tag == TAG_MMS_STRING:
        return MmsStringData(value.decode("utf-8", errors="replace"))
    if tag == TAG_UTC_TIME and len(value) >= 8:
        dt, quality = decode_utc_time(value)
        return TimestampData(dt, quality)
    if tag == TAG_ARRAY:
        return ArrayData(decode_data_sequence(value))
    if tag == TAG_STRUCTURE:
        return StructureData(decode_data_sequence(value))
    return RawData(tag, bytes(value))


def decode_data_at(data: bytes, offset: int = 0) -> tuple[IECData, int]:
    """Decode the ``Data`` TLV at ``offset``; return it with the next offset."""
    tlv = ber.decode_tlv(data, offset)
    return decode_data(tlv.tag, tlv.value), tlv.end


def decode_data_sequence(data: bytes) -> list[IECData]:
    """Decode consecutive ``Data`` TLVs; raise :class:`ber.BerError` if malformed."""
    return [decode_data(tlv.tag, tlv.value) for tlv in ber.iter_tlvs(data)]


# --- encoding ----------------------------------------------------------------


def encode_data(d: IECData) -> bytes:
    """Encode one ``Data`` value as a TLV."""
    if isinstance(d, BoolData):
        return ber.encode_tlv(TAG_BOOLEAN, ber.encode_boolean(d.value))
    if isinstance(d, IntData):
        return ber.encode_tlv(TAG_INTEGER, ber.encode_integer(d.value))
    if isinstance(d, UIntData):
        return ber.encode_tlv(TAG_UNSIGNED, ber.encode_unsigned(d.value))
    if isinstance(d, FloatData):
        if d.double:
            return ber.encode_tlv(TAG_FLOAT, bytes([_FLOAT64_FORMAT]) + struct.pack("!d", d.value))
        return ber.encode_tlv(TAG_FLOAT, bytes([_FLOAT32_FORMAT]) + struct.pack("!f", d.value))
    if isinstance(d, BitStringData):
        if not 0 <= d.unused_bits <= 7:
            raise ValueError(f"unused_bits must be 0..7, got {d.unused_bits}")
        return ber.encode_tlv(TAG_BIT_STRING, bytes([d.unused_bits]) + d.value)
    if isinstance(d, OctetStringData):
        return ber.encode_tlv(TAG_OCTET_STRING, d.value)
    if isinstance(d, VisibleStringData):
        return ber.encode_tlv(TAG_VISIBLE_STRING, d.value.encode("ascii", errors="replace"))
    if isinstance(d, MmsStringData):
        return ber.encode_tlv(TAG_MMS_STRING, d.value.encode("utf-8"))
    if isinstance(d, TimestampData):
        return ber.encode_tlv(TAG_UTC_TIME, encode_utc_time(d.value, d.quality))
    if isinstance(d, StructureData):
        return ber.encode_tlv(TAG_STRUCTURE, b"".join(encode_data(m) for m in d.members))
    if isinstance(d, ArrayData):
        return ber.encode_tlv(TAG_ARRAY, b"".join(encode_data(e) for e in d.elements))
    if isinstance(d, RawData):
        return ber.encode_tlv(d.tag, d.value)
    raise TypeError(f"not an IEC 61850 Data value: {d!r}")

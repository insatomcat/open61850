# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Quality (IEC 61850-7-3) and TimeQuality (IEC 61850-8-1) decoding.

Quality is a 13-bit bit string::

    0-1 validity (00 good, 01 invalid, 10 reserved, 11 questionable)
    2 overflow, 3 outOfRange, 4 badReference, 5 oscillatory, 6 failure,
    7 oldData, 8 inconsistent, 9 inaccurate, 10 source (1 = substituted),
    11 test, 12 operatorBlocked

TimeQuality is the last octet of a UtcTime: bit 7 LeapSecondsKnown, bit 6
ClockFailure, bit 5 ClockNotSynchronized, bits 4-0 TimeAccuracy (number of
significant bits of the fraction of second; 31 = unspecified).
"""

from __future__ import annotations

from dataclasses import dataclass

from .data import BitStringData

VALIDITY = ("good", "invalid", "reserved", "questionable")
_DETAILS = (
    "overflow", "out-of-range", "bad-reference", "oscillatory", "failure",
    "old-data", "inconsistent", "inaccurate",
)


def _bit(raw: bytes, index: int) -> bool:
    return index // 8 < len(raw) and bool(raw[index // 8] & (0x80 >> (index % 8)))


@dataclass(frozen=True)
class Quality:
    validity: str
    details: tuple[str, ...] = ()
    substituted: bool = False
    test: bool = False
    operator_blocked: bool = False

    @classmethod
    def from_bitstring(cls, value: BitStringData) -> Quality:
        raw = value.value
        validity = VALIDITY[(_bit(raw, 0) << 1) | _bit(raw, 1)]
        details = tuple(name for i, name in enumerate(_DETAILS, start=2) if _bit(raw, i))
        return cls(validity, details, _bit(raw, 10), _bit(raw, 11), _bit(raw, 12))

    def __str__(self) -> str:
        flags = list(self.details)
        if self.substituted:
            flags.append("substituted")
        if self.test:
            flags.append("test")
        if self.operator_blocked:
            flags.append("operator-blocked")
        return ",".join([self.validity, *flags])


@dataclass(frozen=True)
class TimeQuality:
    leap_seconds_known: bool
    clock_failure: bool
    clock_not_synchronized: bool
    accuracy_bits: int

    @classmethod
    def from_octet(cls, octet: int) -> TimeQuality:
        return cls(bool(octet & 0x80), bool(octet & 0x40), bool(octet & 0x20), octet & 0x1F)

    def __str__(self) -> str:
        flags = []
        if self.clock_failure:
            flags.append("clock-failure")
        if self.clock_not_synchronized:
            flags.append("not-synchronized")
        if self.accuracy_bits != 31:
            flags.append(f"accuracy={self.accuracy_bits}bits")
        return ",".join(flags) or "ok"

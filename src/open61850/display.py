# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Human-readable rendering of IEC 61850 values."""

from __future__ import annotations

from typing import Optional

from .data import BitStringData, IECData, OctetStringData, TimestampData
from .mms.types import MmsType, label
from .quality import Quality, TimeQuality

__all__ = [
    "DBPOS",
    "format_leaf",
    "format_value",
]



DBPOS = ("intermediate", "off", "on", "bad")
_OCTETS_SHOWN = 16


def format_leaf(path: str, value: IECData) -> str:
    """One primitive value.

    ``q`` leaves are shown as Quality, 2-bit ``stVal`` leaves as a double point
    position (Dbpos), timestamps with their TimeQuality.
    """
    last = path.rsplit(".", 1)[-1]
    if isinstance(value, BitStringData) and last == "q":
        return str(Quality.from_bitstring(value))
    if isinstance(value, BitStringData) and last == "stVal" and 8 * len(value.value) - value.unused_bits == 2:
        return DBPOS[value.value[0] >> 6]
    if isinstance(value, OctetStringData):
        if value.value and not any(value.value):
            return f"zeros({len(value.value)})"
        if len(value.value) > _OCTETS_SHOWN:
            return f"0x{value.value[:_OCTETS_SHOWN].hex()}...({len(value.value)} bytes)"
        return f"0x{value.value.hex()}"
    if isinstance(value, TimestampData):
        text = value.value.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        return f"{text} [{TimeQuality.from_octet(value.quality)}]"
    if isinstance(value, BitStringData):
        return f"bits:{value.value.hex()}/{8 * len(value.value) - value.unused_bits}"
    inner = getattr(value, "value", value)
    return repr(inner) if isinstance(inner, str) else str(inner)


def format_value(value: IECData, mms_type: Optional[MmsType]) -> str:
    """One line with every leaf named after the type (numbered when the type is unknown)."""
    return "  ".join(
        f"{path}={format_leaf(path, leaf)}" if path else format_leaf(path, leaf)
        for path, leaf in label(value, mms_type)
    )

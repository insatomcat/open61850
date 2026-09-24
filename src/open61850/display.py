# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Human-readable rendering of IEC 61850 values."""

from __future__ import annotations

from typing import Optional

from .data import BitStringData, IECData, TimestampData
from .mms.types import MmsType, label
from .quality import Quality, TimeQuality


def format_leaf(path: str, value: IECData) -> str:
    """One primitive value; ``q`` leaves are shown as Quality, timestamps with their TimeQuality."""
    if isinstance(value, BitStringData) and path.rsplit(".", 1)[-1] == "q":
        return str(Quality.from_bitstring(value))
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

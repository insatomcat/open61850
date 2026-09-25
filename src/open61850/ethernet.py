# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Ethernet II / IEEE 802.1Q framing shared by GOOSE and Sampled Values.

Layout after the MAC addresses and the optional VLAN tag (IEC 61850-8-1
annex C, IEC 61850-9-2 clause 8)::

    EtherType (2) | APPID (2) | Length (2) | Reserved 1 (2) | Reserved 2 (2) | APDU

``Length`` counts from APPID to the end of the APDU, so it is ``8 + len(APDU)``.
Frames shorter than 60 bytes are padded by the NIC on transmit and arrive with
trailing padding, which the parser ignores thanks to ``Length``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "ETHERTYPE_VLAN",
    "ETHERTYPE_GOOSE",
    "ETHERTYPE_GSE_MGMT",
    "ETHERTYPE_SV",
    "mac_to_bytes",
    "mac_to_str",
    "EthernetFrame",
    "parse_frame",
    "build_frame",
]


ETHERTYPE_VLAN = 0x8100
ETHERTYPE_GOOSE = 0x88B8
ETHERTYPE_GSE_MGMT = 0x88B9
ETHERTYPE_SV = 0x88BA

_HEADER_LEN = 8  # APPID + Length + Reserved 1 + Reserved 2


def mac_to_bytes(mac: str) -> bytes:
    parts = mac.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address {mac!r}")
    return bytes(int(p, 16) for p in parts)


def mac_to_str(mac: bytes) -> str:
    return bytes(mac).hex(":")


@dataclass(frozen=True)
class EthernetFrame:
    """A decoded GOOSE or SV frame, up to the APDU."""

    dst_mac: str
    src_mac: str
    vlan_id: Optional[int]
    vlan_priority: Optional[int]
    ethertype: int
    app_id: int
    reserved1: int
    reserved2: int
    apdu: bytes


def parse_frame(raw: bytes, ethertypes: tuple[int, ...] = (ETHERTYPE_GOOSE, ETHERTYPE_SV)) -> Optional[EthernetFrame]:
    """Parse an Ethernet frame carrying one of ``ethertypes``; ``None`` otherwise.

    ``None`` is also returned for truncated frames or an inconsistent Length,
    so a capture loop can feed every frame without try/except.
    """
    if len(raw) < 14:
        return None
    offset = 12
    ethertype = int.from_bytes(raw[offset : offset + 2], "big")
    offset += 2
    vlan_id: Optional[int] = None
    vlan_priority: Optional[int] = None
    if ethertype == ETHERTYPE_VLAN:
        if len(raw) < offset + 4:
            return None
        tci = int.from_bytes(raw[offset : offset + 2], "big")
        vlan_id = tci & 0x0FFF
        vlan_priority = tci >> 13
        ethertype = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        offset += 4
    if ethertype not in ethertypes:
        return None
    if len(raw) < offset + _HEADER_LEN:
        return None
    app_id = int.from_bytes(raw[offset : offset + 2], "big")
    length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
    if length < _HEADER_LEN or offset + length > len(raw):
        return None
    return EthernetFrame(
        dst_mac=mac_to_str(raw[0:6]),
        src_mac=mac_to_str(raw[6:12]),
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
        ethertype=ethertype,
        app_id=app_id,
        reserved1=int.from_bytes(raw[offset + 4 : offset + 6], "big"),
        reserved2=int.from_bytes(raw[offset + 6 : offset + 8], "big"),
        apdu=bytes(raw[offset + _HEADER_LEN : offset + length]),
    )


def build_frame(
    *,
    dst_mac: str,
    src_mac: str,
    ethertype: int,
    app_id: int,
    apdu: bytes,
    vlan_id: Optional[int] = None,
    vlan_priority: Optional[int] = None,
    reserved1: int = 0,
    reserved2: int = 0,
) -> bytes:
    """Build a GOOSE or SV frame (without FCS or padding)."""
    if not 0 <= app_id <= 0xFFFF:
        raise ValueError(f"APPID out of range: {app_id}")
    length = _HEADER_LEN + len(apdu)
    if length > 0xFFFF:
        raise ValueError(f"APDU too long: {len(apdu)} bytes")
    frame = bytearray(mac_to_bytes(dst_mac) + mac_to_bytes(src_mac))
    if vlan_id is not None:
        if not 0 <= vlan_id <= 0x0FFF:
            raise ValueError(f"VLAN id out of range: {vlan_id}")
        prio = vlan_priority or 0
        if not 0 <= prio <= 7:
            raise ValueError(f"VLAN priority out of range: {prio}")
        frame += ETHERTYPE_VLAN.to_bytes(2, "big") + ((prio << 13) | vlan_id).to_bytes(2, "big")
    frame += ethertype.to_bytes(2, "big")
    frame += app_id.to_bytes(2, "big") + length.to_bytes(2, "big")
    frame += reserved1.to_bytes(2, "big") + reserved2.to_bytes(2, "big")
    frame += apdu
    return bytes(frame)

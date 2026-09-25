# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Sampled Values PDU and frame codec (IEC 61850-9-2, IEC 61869-9).

::

    SavPdu ::= [APPLICATION 0] IMPLICIT SEQUENCE {
        noASDU    [0] IMPLICIT INTEGER (1..65535),
        security  [1] ANY OPTIONAL,
        asdu      [2] IMPLICIT SEQUENCE OF ASDU
    }
    ASDU ::= SEQUENCE {
        svID       [0] VisibleString,
        datSet     [1] VisibleString OPTIONAL,
        smpCnt     [2] OCTET STRING (SIZE(2)),
        confRev    [3] OCTET STRING (SIZE(4)),
        refrTm     [4] UtcTime OPTIONAL,
        smpSynch   [5] OCTET STRING (SIZE(1)),
        smpRate    [6] OCTET STRING (SIZE(2)) OPTIONAL,
        sample     [7] OCTET STRING,              -- seqData
        smpMod     [8] OCTET STRING (SIZE(2)) OPTIONAL,
        gmIdentity [9] OCTET STRING (SIZE(8)) OPTIONAL   -- IEC 61869-9
    }

``sample`` is kept as raw bytes: its layout depends on the data set. The
9-2LE and IEC 61869-9 profiles use pairs of INT32 value and 32-bit quality,
see :func:`decode_int32_samples`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from . import ber, ethernet
from .data import decode_utc_time, encode_utc_time

__all__ = [
    "TAG_SAV_PDU",
    "SMP_SYNCH_NONE",
    "SMP_SYNCH_LOCAL",
    "SMP_SYNCH_GLOBAL",
    "SvDecodeError",
    "SvAsdu",
    "SvPDU",
    "decode_sv_pdu",
    "encode_sv_pdu",
    "encode_sv_frame",
    "decode_sv_frame",
    "decode_int32_samples",
    "encode_int32_samples",
]


TAG_SAV_PDU = 0x60
_TAG_NO_ASDU = 0x80
_TAG_SECURITY = 0xA1
_TAG_SEQ_ASDU = 0xA2
_TAG_ASDU = 0x30

SMP_SYNCH_NONE = 0
SMP_SYNCH_LOCAL = 1
SMP_SYNCH_GLOBAL = 2


class SvDecodeError(ber.BerError):
    """The bytes are not a valid Sampled Values PDU."""


@dataclass
class SvAsdu:
    sv_id: str
    smp_cnt: int
    conf_rev: int
    smp_synch: int
    sample: bytes
    dat_set: Optional[str] = None
    refr_tm: Optional[datetime] = None
    smp_rate: Optional[int] = None
    smp_mod: Optional[int] = None
    gm_identity: Optional[bytes] = None


@dataclass
class SvPDU:
    asdus: list[SvAsdu] = field(default_factory=list)
    security: Optional[bytes] = None


def _fixed(content: bytes, size: int, name: str) -> int:
    if len(content) != size:
        raise SvDecodeError(f"{name} must be {size} bytes, got {len(content)}")
    return int.from_bytes(content, "big")


def _asdu_fields(content: bytes) -> dict[int, bytes]:
    """Content of each ASDU field by context number ([0]..[9], tags 0x80..0x89).

    A direct loop over the TLVs: this runs for every ASDU at several thousand
    frames per second. Long lengths and high tag numbers go through ``ber``.
    """
    fields: dict[int, bytes] = {}
    offset, size = 0, len(content)
    while offset < size:
        if offset + 2 <= size and content[offset + 1] < 0x80 and content[offset] & 0x1F != 0x1F:
            tag = content[offset]
            start = offset + 2
            end = start + content[offset + 1]
            if end > size:
                raise SvDecodeError(f"ASDU field 0x{tag:X} truncated")
            fields[tag - 0x80] = content[start:end]
        else:
            tlv = ber.decode_tlv(content, offset)
            tag, end = tlv.tag, tlv.end
            fields[tag - 0x80] = tlv.value
        offset = end
    return fields


def _decode_asdu(content: bytes) -> SvAsdu:
    fields = _asdu_fields(content)
    for number, name in ((0, "svID"), (2, "smpCnt"), (3, "confRev"), (5, "smpSynch"), (7, "sample")):
        if number not in fields:
            raise SvDecodeError(f"ASDU without {name}")
    return SvAsdu(
        sv_id=fields[0].decode("ascii", errors="replace"),
        dat_set=fields[1].decode("ascii", errors="replace") if 1 in fields else None,
        smp_cnt=_fixed(fields[2], 2, "smpCnt"),
        conf_rev=_fixed(fields[3], 4, "confRev"),
        refr_tm=decode_utc_time(fields[4])[0] if 4 in fields else None,
        smp_synch=_fixed(fields[5], 1, "smpSynch"),
        smp_rate=_fixed(fields[6], 2, "smpRate") if 6 in fields else None,
        sample=fields[7],
        smp_mod=_fixed(fields[8], 2, "smpMod") if 8 in fields else None,
        gm_identity=fields[9] if 9 in fields else None,
    )


def decode_sv_pdu(apdu: bytes) -> SvPDU:
    """Decode a ``SavPdu`` (the bytes after the 8-byte APPID header)."""
    try:
        outer = ber.expect_tlv(apdu, 0, TAG_SAV_PDU)
        no_asdu: Optional[int] = None
        security: Optional[bytes] = None
        asdus: list[SvAsdu] = []
        for tlv in ber.iter_tlvs(outer.value):
            if tlv.tag == _TAG_NO_ASDU:
                no_asdu = ber.decode_unsigned(tlv.value)
            elif tlv.tag == _TAG_SECURITY:
                security = tlv.value
            elif tlv.tag == _TAG_SEQ_ASDU:
                for item in ber.iter_tlvs(tlv.value):
                    if item.tag != _TAG_ASDU:
                        raise SvDecodeError(f"unexpected tag 0x{item.tag:X} in seqASDU")
                    asdus.append(_decode_asdu(item.value))
    except ber.BerError as exc:
        raise SvDecodeError(str(exc)) from exc
    if no_asdu is None:
        raise SvDecodeError("SavPdu without noASDU")
    if no_asdu != len(asdus):
        raise SvDecodeError(f"noASDU={no_asdu} but {len(asdus)} ASDUs present")
    return SvPDU(asdus=asdus, security=security)


def _encode_asdu(asdu: SvAsdu) -> bytes:
    def ctx(number: int, content: bytes) -> bytes:
        return ber.encode_tlv(ber.make_tag(number), content)

    parts = [ctx(0, asdu.sv_id.encode("ascii"))]
    if asdu.dat_set is not None:
        parts.append(ctx(1, asdu.dat_set.encode("ascii")))
    parts += [ctx(2, asdu.smp_cnt.to_bytes(2, "big")), ctx(3, asdu.conf_rev.to_bytes(4, "big"))]
    if asdu.refr_tm is not None:
        parts.append(ctx(4, encode_utc_time(asdu.refr_tm)))
    parts.append(ctx(5, asdu.smp_synch.to_bytes(1, "big")))
    if asdu.smp_rate is not None:
        parts.append(ctx(6, asdu.smp_rate.to_bytes(2, "big")))
    parts.append(ctx(7, asdu.sample))
    if asdu.smp_mod is not None:
        parts.append(ctx(8, asdu.smp_mod.to_bytes(2, "big")))
    if asdu.gm_identity is not None:
        if len(asdu.gm_identity) != 8:
            raise ValueError("gmIdentity must be 8 bytes")
        parts.append(ctx(9, asdu.gm_identity))
    return ber.encode_tlv(_TAG_ASDU, b"".join(parts))


def encode_sv_pdu(pdu: SvPDU) -> bytes:
    if not pdu.asdus:
        raise ValueError("a SavPdu carries at least one ASDU")
    parts = [ber.encode_tlv(_TAG_NO_ASDU, ber.encode_unsigned(len(pdu.asdus)))]
    if pdu.security is not None:
        parts.append(ber.encode_tlv(_TAG_SECURITY, pdu.security))
    parts.append(ber.encode_tlv(_TAG_SEQ_ASDU, b"".join(_encode_asdu(a) for a in pdu.asdus)))
    return ber.encode_tlv(TAG_SAV_PDU, b"".join(parts))


def encode_sv_frame(
    pdu: SvPDU,
    *,
    dst_mac: str,
    src_mac: str,
    app_id: int,
    vlan_id: Optional[int] = None,
    vlan_priority: Optional[int] = None,
) -> bytes:
    return ethernet.build_frame(
        dst_mac=dst_mac,
        src_mac=src_mac,
        ethertype=ethernet.ETHERTYPE_SV,
        app_id=app_id,
        apdu=encode_sv_pdu(pdu),
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )


def decode_sv_frame(raw: bytes) -> Optional[tuple[ethernet.EthernetFrame, SvPDU]]:
    """Decode an SV Ethernet frame; ``None`` if the frame is not SV."""
    frame = ethernet.parse_frame(raw, (ethernet.ETHERTYPE_SV,))
    if frame is None:
        return None
    return frame, decode_sv_pdu(frame.apdu)


# --- INT32 + quality samples (9-2LE, IEC 61869-9) ----------------------------


def decode_int32_samples(sample: bytes) -> list[tuple[int, int]]:
    """Split ``sample`` into ``(value, quality)`` pairs of INT32 and 32-bit quality."""
    if len(sample) % 8:
        raise SvDecodeError(f"sample length {len(sample)} is not a multiple of 8")
    return list(struct.iter_unpack("!iI", sample))


def encode_int32_samples(values: list[tuple[int, int]]) -> bytes:
    return b"".join(struct.pack("!iI", v, q) for v, q in values)

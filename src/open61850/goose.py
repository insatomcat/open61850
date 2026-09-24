# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""GOOSE PDU and frame codec (IEC 61850-8-1, clause A.3 ``IECGoosePdu``).

::

    IECGoosePdu ::= [APPLICATION 1] IMPLICIT SEQUENCE {
        gocbRef           [0]  VisibleString,
        timeAllowedtoLive [1]  INTEGER,
        datSet            [2]  VisibleString,
        goID              [3]  VisibleString OPTIONAL,
        t                 [4]  UtcTime,
        stNum             [5]  INTEGER,
        sqNum             [6]  INTEGER,
        simulation        [7]  BOOLEAN DEFAULT FALSE,   -- "test" in edition 1
        confRev           [8]  INTEGER,
        ndsCom            [9]  BOOLEAN DEFAULT FALSE,
        numDatSetEntries  [10] INTEGER,
        allData           [11] SEQUENCE OF Data,
        ...
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import ber, ethernet
from .data import DATA_TYPES, IECData, decode_data_sequence, decode_utc_time, encode_data, encode_utc_time

TAG_GOOSE_PDU = 0x61

_GOCB_REF = 0
_TAL = 1
_DAT_SET = 2
_GO_ID = 3
_T = 4
_ST_NUM = 5
_SQ_NUM = 6
_SIMULATION = 7
_CONF_REV = 8
_NDS_COM = 9
_NUM_ENTRIES = 10
_ALL_DATA = 11

_MANDATORY = (_GOCB_REF, _TAL, _DAT_SET, _T, _ST_NUM, _SQ_NUM, _CONF_REV, _NUM_ENTRIES)


class GooseDecodeError(ber.BerError):
    """The bytes are not a valid GOOSE PDU."""


@dataclass
class GoosePDU:
    """Content of one GOOSE message.

    ``timestamp`` is ``t``: the time of the last stNum change.
    ``time_quality`` is the TimeQuality octet of ``t``.
    """

    gocb_ref: str
    time_allowed_to_live: int
    dat_set: str
    go_id: Optional[str]
    timestamp: datetime
    st_num: int
    sq_num: int
    simulation: bool
    conf_rev: int
    nds_com: bool
    num_dat_set_entries: int
    all_data: list[IECData] = field(default_factory=list)
    time_quality: int = 0


def decode_goose_pdu(apdu: bytes) -> GoosePDU:
    """Decode an ``IECGoosePdu`` (the bytes after the 8-byte APPID header)."""
    try:
        outer = ber.expect_tlv(apdu, 0, TAG_GOOSE_PDU)
        fields: dict[int, bytes] = {}
        for tlv in ber.iter_tlvs(outer.value):
            fields[ber.tag_number(tlv.tag)] = tlv.value
    except ber.BerError as exc:
        raise GooseDecodeError(str(exc)) from exc

    missing = [n for n in _MANDATORY if n not in fields]
    if missing:
        raise GooseDecodeError(f"missing mandatory GOOSE fields {missing}")

    try:
        timestamp, time_quality = decode_utc_time(fields[_T])
        return GoosePDU(
            gocb_ref=fields[_GOCB_REF].decode("ascii", errors="replace"),
            time_allowed_to_live=ber.decode_unsigned(fields[_TAL]),
            dat_set=fields[_DAT_SET].decode("ascii", errors="replace"),
            go_id=fields[_GO_ID].decode("ascii", errors="replace") if _GO_ID in fields else None,
            timestamp=timestamp,
            st_num=ber.decode_unsigned(fields[_ST_NUM]),
            sq_num=ber.decode_unsigned(fields[_SQ_NUM]),
            simulation=_lenient_bool(fields.get(_SIMULATION)),
            conf_rev=ber.decode_unsigned(fields[_CONF_REV]),
            nds_com=_lenient_bool(fields.get(_NDS_COM)),
            num_dat_set_entries=ber.decode_unsigned(fields[_NUM_ENTRIES]),
            all_data=decode_data_sequence(fields.get(_ALL_DATA, b"")),
            time_quality=time_quality,
        )
    except ber.BerError as exc:
        raise GooseDecodeError(str(exc)) from exc


def _lenient_bool(content: Optional[bytes]) -> bool:
    return bool(content) and content[0] != 0  # type: ignore[index]


def encode_goose_pdu(pdu: GoosePDU) -> bytes:
    """Encode a :class:`GoosePDU` into an ``IECGoosePdu``."""
    for item in pdu.all_data:
        if not isinstance(item, DATA_TYPES):
            raise TypeError(f"allData items must be IEC 61850 Data values, got {item!r}")

    def ctx(number: int, content: bytes, constructed: bool = False) -> bytes:
        return ber.encode_tlv(ber.make_tag(number, constructed=constructed), content)

    parts = [
        ctx(_GOCB_REF, pdu.gocb_ref.encode("ascii")),
        ctx(_TAL, ber.encode_unsigned(pdu.time_allowed_to_live)),
        ctx(_DAT_SET, pdu.dat_set.encode("ascii")),
    ]
    if pdu.go_id is not None:
        parts.append(ctx(_GO_ID, pdu.go_id.encode("ascii")))
    timestamp = pdu.timestamp if pdu.timestamp.tzinfo else pdu.timestamp.replace(tzinfo=timezone.utc)
    parts += [
        ctx(_T, encode_utc_time(timestamp, pdu.time_quality)),
        ctx(_ST_NUM, ber.encode_unsigned(pdu.st_num)),
        ctx(_SQ_NUM, ber.encode_unsigned(pdu.sq_num)),
        ctx(_SIMULATION, ber.encode_boolean(pdu.simulation)),
        ctx(_CONF_REV, ber.encode_unsigned(pdu.conf_rev)),
        ctx(_NDS_COM, ber.encode_boolean(pdu.nds_com)),
        ctx(_NUM_ENTRIES, ber.encode_unsigned(pdu.num_dat_set_entries)),
    ]
    all_data = b"".join(encode_data(d) for d in pdu.all_data)
    if all_data:
        parts.append(ctx(_ALL_DATA, all_data, constructed=True))
    return ber.encode_tlv(TAG_GOOSE_PDU, b"".join(parts))


def encode_goose_frame(
    pdu: GoosePDU,
    *,
    dst_mac: str,
    src_mac: str,
    app_id: int,
    vlan_id: Optional[int] = None,
    vlan_priority: Optional[int] = None,
) -> bytes:
    """Encode a complete GOOSE Ethernet frame."""
    return ethernet.build_frame(
        dst_mac=dst_mac,
        src_mac=src_mac,
        ethertype=ethernet.ETHERTYPE_GOOSE,
        app_id=app_id,
        apdu=encode_goose_pdu(pdu),
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )


def decode_goose_frame(raw: bytes) -> Optional[tuple[ethernet.EthernetFrame, GoosePDU]]:
    """Decode a GOOSE Ethernet frame; ``None`` if the frame is not GOOSE.

    Raises :class:`GooseDecodeError` when the frame is GOOSE but its PDU is invalid.
    """
    frame = ethernet.parse_frame(raw, (ethernet.ETHERTYPE_GOOSE,))
    if frame is None:
        return None
    return frame, decode_goose_pdu(frame.apdu)

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

__all__ = [
    "TAG_GOOSE_PDU",
    "GooseDecodeError",
    "GoosePDU",
    "decode_goose_pdu",
    "encode_goose_pdu",
    "encode_goose_frame",
    "decode_goose_frame",
]


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


def decode_goose_pdu(apdu: bytes, *, strict: bool = False) -> GoosePDU:
    """Decode an ``IECGoosePdu`` (the bytes after the 8-byte APPID header).

    By default the decoding is lenient, for diagnosis: fields are found by
    tag number whatever their order, class or form, and only what is needed
    to read them is checked. ``strict=True`` also refuses what IEC 61850-8-1
    does not allow (see :func:`_check_strict`), as a protection function
    should before acting on a message.
    """
    pdu = _decode_goose_pdu(apdu)
    if strict:
        _check_strict(apdu)
    return pdu


def _decode_goose_pdu(apdu: bytes) -> GoosePDU:
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
            time_allowed_to_live=_counter(fields[_TAL], "timeAllowedtoLive"),
            dat_set=fields[_DAT_SET].decode("ascii", errors="replace"),
            go_id=fields[_GO_ID].decode("ascii", errors="replace") if _GO_ID in fields else None,
            timestamp=timestamp,
            st_num=_counter(fields[_ST_NUM], "stNum"),
            sq_num=_counter(fields[_SQ_NUM], "sqNum"),
            simulation=_lenient_bool(fields.get(_SIMULATION)),
            conf_rev=_counter(fields[_CONF_REV], "confRev"),
            nds_com=_lenient_bool(fields.get(_NDS_COM)),
            num_dat_set_entries=_counter(fields[_NUM_ENTRIES], "numDatSetEntries"),
            all_data=decode_data_sequence(fields.get(_ALL_DATA, b"")),
            time_quality=time_quality,
        )
    except ber.BerError as exc:
        raise GooseDecodeError(str(exc)) from exc


def _counter(content: bytes, name: str) -> int:
    """An INT32U header field, read leniently but refused above 64 bits."""
    value = ber.decode_unsigned(content)
    if value >> 64:
        raise GooseDecodeError(f"{name} above 64 bits")
    return value


def _lenient_bool(content: Optional[bytes]) -> bool:
    return bool(content) and content[0] != 0  # type: ignore[index]


_STRING_MAX = 129  # VisibleString129: gocbRef, datSet, goID
_U32_OCTETS = 5    # an INT32U: 4 octets, and a leading 00 when the high bit is set
# Sizes of the primitive Data types whose size IEC 61850-8-1 fixes.
_DATA_SIZES = {0x83: (1,), 0x87: (5, 9), 0x8C: (4, 6), 0x91: (8,)}


def _strict_error(message: str) -> GooseDecodeError:
    return GooseDecodeError(f"not conformant: {message}")


def _visible(value: bytes) -> bool:
    return all(0x20 <= c <= 0x7E for c in value)


def _check_strict(apdu: bytes) -> None:
    """What a lenient decoding accepts but IEC 61850-8-1 does not.

    The PDU ends where the APDU does (the header Length covers it exactly);
    fields are the SEQUENCE's: tags ``80``..``8a`` and ``ab`` in increasing
    order, nothing else; gocbRef, datSet and goID are VisibleString129
    (gocbRef not empty); t is 8 octets; the counters are INT32U; simulation
    and ndsCom, when present, are one octet; allData is present and holds
    numDatSetEntries values, each a context-specific Data, constructed for a
    structure or an array only, with the size its type fixes (BOOLEAN,
    floats, times), a BIT STRING of at least one octet and at most 7 unused
    bits, an INTEGER of at least one octet, a VisibleString in its alphabet.
    Any depth and any definite length form are accepted.
    """
    outer = ber.decode_tlv(apdu, 0)
    if outer.end != len(apdu):
        raise _strict_error(f"{len(apdu) - outer.end} octets after the PDU")
    fields: dict[int, bytes] = {}
    previous = -1
    for tlv in ber.iter_tlvs(outer.value):
        number = tlv.tag & 0x1F
        expected = 0xAB if number == _ALL_DATA else 0x80 | number
        if tlv.tag != expected or number > _ALL_DATA:
            raise _strict_error(f"tag 0x{tlv.tag:X} is not a GOOSE field")
        if number <= previous:
            raise _strict_error(f"field [{number}] after [{previous}]")
        previous = number
        fields[number] = tlv.value
    for number, name in ((_GOCB_REF, "gocbRef"), (_DAT_SET, "datSet"), (_GO_ID, "goID")):
        value = fields.get(number, b"")
        if len(value) > _STRING_MAX or not _visible(value):
            raise _strict_error(f"{name} is not a VisibleString129")
    if not fields[_GOCB_REF]:
        raise _strict_error("empty gocbRef")
    if len(fields[_T]) != 8:
        raise _strict_error(f"t of {len(fields[_T])} octets")
    for number, name in ((_TAL, "timeAllowedtoLive"), (_ST_NUM, "stNum"), (_SQ_NUM, "sqNum"),
                         (_CONF_REV, "confRev"), (_NUM_ENTRIES, "numDatSetEntries")):
        value = fields[number]
        if len(value) > _U32_OCTETS or (len(value) == _U32_OCTETS and value[0] != 0):
            raise _strict_error(f"{name} above 32 bits")
    for number, name in ((_SIMULATION, "simulation"), (_NDS_COM, "ndsCom")):
        if number in fields and len(fields[number]) != 1:
            raise _strict_error(f"{name} of {len(fields[number])} octets")
    if _ALL_DATA not in fields:
        raise _strict_error("no allData")
    entries = sum(1 for _ in ber.iter_tlvs(fields[_ALL_DATA]))
    if entries != ber.decode_unsigned(fields[_NUM_ENTRIES]):
        raise _strict_error(f"numDatSetEntries={ber.decode_unsigned(fields[_NUM_ENTRIES])} "
                            f"but {entries} entries")
    _check_strict_data(fields[_ALL_DATA])


def _check_strict_data(all_data: bytes) -> None:
    """Every Data of allData in preorder: one pass, stepping into structures
    (the lenient decoding checked that their members tile them)."""
    at = 0
    while at < len(all_data):
        tlv = ber.decode_tlv(all_data, at)
        tag, value = tlv.tag, tlv.value
        container = tag & 0x1F in (1, 2)  # [1] array and [2] structure: constructed, and only they
        if tag > 0xFF or tag & 0xC0 != 0x80 or tag & 0x1F == 0x1F or bool(tag & 0x20) != container:
            raise _strict_error(f"allData tag 0x{tag:X} is not a Data")
        if container:
            at = tlv.end - len(value)
            continue
        if tag in _DATA_SIZES and len(value) not in _DATA_SIZES[tag]:
            raise _strict_error(f"allData value 0x{tag:X} of {len(value)} octets")
        if tag == 0x84 and (not value or value[0] > 7):
            raise _strict_error("allData BIT STRING without a valid unused-bits octet")
        if tag in (0x85, 0x86) and not value:
            raise _strict_error("empty allData INTEGER")
        if tag == 0x8A and not _visible(value):
            raise _strict_error("allData VisibleString outside its alphabet")
        at = tlv.end


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
    # allData is not OPTIONAL in IEC 61850-8-1: an empty data set is written as ab 00.
    parts.append(ctx(_ALL_DATA, b"".join(encode_data(d) for d in pdu.all_data), constructed=True))
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


def decode_goose_frame(raw: bytes, *, strict: bool = False) -> Optional[tuple[ethernet.EthernetFrame, GoosePDU]]:
    """Decode a GOOSE Ethernet frame; ``None`` if the frame is not GOOSE.

    Raises :class:`GooseDecodeError` when the frame is GOOSE but its PDU is
    invalid (or, with ``strict=True``, not conformant: see :func:`decode_goose_pdu`).
    """
    frame = ethernet.parse_frame(raw, (ethernet.ETHERTYPE_GOOSE,))
    if frame is None:
        return None
    return frame, decode_goose_pdu(frame.apdu, strict=strict)

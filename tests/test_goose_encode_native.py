# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850-core's GOOSE encoder writes the octets open61850.goose writes.

Random messages with every Data type, nested structures and arrays, values
at the INTEGER and length boundaries, VisibleStrings with non-ASCII
characters and frames with or without VLAN tag: same PDU, same frame. What
Python refuses (unused bits above 7, VLAN out of range, APDU too long), the
native encoder refuses too.
"""

from __future__ import annotations

import math
import random
from datetime import datetime, timedelta, timezone

import pytest

from open61850 import goose
from open61850.data import (
    ArrayData,
    BitStringData,
    BoolData,
    FloatData,
    IECData,
    IntData,
    MmsStringData,
    OctetStringData,
    RawData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
)
from open61850.ethernet import mac_to_bytes

rt = pytest.importorskip("open61850_rt")

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DST, SRC = "01:0c:cd:01:00:01", "02:00:00:00:00:01"


def _u32(rng: random.Random) -> int:
    return rng.choice([0, 1, 127, 128, 255, 256, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                       rng.randint(0, 0xFFFFFFFF)])


def _time(rng: random.Random) -> datetime:
    return EPOCH + timedelta(seconds=rng.randint(0, 0xFFFFFFFF), microseconds=rng.randint(0, 999_999))


def _text(rng: random.Random, n: int, alphabet: str) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _length(rng: random.Random) -> int:
    return rng.choice([0, 1, 5, 127, 128, 255, 256, 300])


def _leaf(rng: random.Random) -> IECData:
    kind = rng.randrange(11)
    if kind == 0:
        return BoolData(rng.random() < 0.5)
    if kind == 1:
        return IntData(rng.choice([0, -1, 127, 128, -128, -129, 2**31 - 1, -(2**31), 2**63 - 1, -(2**63),
                                   rng.randint(-(2**63), 2**63 - 1)]))
    if kind == 2:
        return UIntData(rng.choice([0, 127, 128, 255, 2**32 - 1, 2**63, 2**64 - 1, rng.randint(0, 2**64 - 1)]))
    if kind == 3:
        value = rng.choice([0.0, -0.0, 1.1, -1e-45, 3.4e38, math.inf, -math.inf, rng.uniform(-1e6, 1e6)])
        return FloatData(value, double=rng.random() < 0.3)
    if kind == 4:
        return BitStringData(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 4))), rng.randint(0, 7))
    if kind == 5:
        return OctetStringData(bytes(rng.getrandbits(8) for _ in range(_length(rng))))
    if kind == 6:
        return VisibleStringData(_text(rng, _length(rng), "abcXYZ019$/._ é€\x00\x7f"))
    if kind == 7:
        return MmsStringData(_text(rng, rng.randint(0, 20), "abc é€\U0001f600"))
    if kind == 8:
        return TimestampData(_time(rng), rng.randint(0, 255))
    if kind == 9:
        tag = rng.choice([0x80, 0x8C, 0x9F20, 0xBF48, 0x1F8148, 0x00])
        return RawData(tag, bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 10))))
    return BoolData(True)


def _data(rng: random.Random, depth: int = 0) -> IECData:
    if depth < 4 and rng.random() < 0.3:
        members = [_data(rng, depth + 1) for _ in range(rng.choice([0, 1, 2, 5]))]
        return StructureData(members) if rng.random() < 0.5 else ArrayData(members)
    return _leaf(rng)


def _message(rng: random.Random) -> goose.GoosePDU:
    all_data = [_data(rng) for _ in range(rng.choice([0, 1, 2, 10, 32]))]
    ascii_text = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789$/_."
    return goose.GoosePDU(
        gocb_ref=_text(rng, rng.choice([0, 16, 64, 129, 200]), ascii_text),
        time_allowed_to_live=_u32(rng),
        dat_set=_text(rng, rng.choice([0, 20, 129]), ascii_text),
        go_id=_text(rng, rng.choice([0, 10, 129]), ascii_text) if rng.random() < 0.7 else None,
        timestamp=_time(rng),
        st_num=_u32(rng),
        sq_num=_u32(rng),
        simulation=rng.random() < 0.5,
        conf_rev=_u32(rng),
        nds_com=rng.random() < 0.5,
        num_dat_set_entries=rng.choice([len(all_data), _u32(rng)]),
        all_data=all_data,
        time_quality=rng.randint(0, 255),
    )


@pytest.mark.parametrize("seed", range(20))
def test_same_octets(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(100):
        pdu = _message(rng)
        assert rt.encode_goose_pdu(pdu) == goose.encode_goose_pdu(pdu), pdu
        vlan = rng.random() < 0.5
        vlan_id = rng.randint(0, 0xFFF) if vlan else None
        prio = rng.choice([None, rng.randint(0, 7)]) if vlan else None
        app_id = rng.randint(0, 0xFFFF)
        expected = goose.encode_goose_frame(pdu, dst_mac=DST, src_mac=SRC, app_id=app_id, vlan_id=vlan_id,
                                            vlan_priority=prio)
        native = rt.encode_goose_frame(pdu, mac_to_bytes(DST), mac_to_bytes(SRC), app_id, vlan_id, prio)
        assert native == expected, pdu


def test_trip_message() -> None:
    """A trip GOOSE as a protection sends it: booleans and their Quality."""
    all_data: list[IECData] = []
    for i in range(5):
        all_data += [BoolData(i == 0), BitStringData(b"\x00\x00", 3)]
    pdu = goose.GoosePDU("IED01PROT/LLN0$GO$gcbTrip", 2000, "IED01PROT/LLN0$DS_TRIP", "IED01_TRIP",
                         datetime(2026, 9, 25, 12, 0, 0, 250000, tzinfo=timezone.utc), 7, 0, False, 1, False, 10,
                         all_data)
    expected = goose.encode_goose_frame(pdu, dst_mac=DST, src_mac=SRC, app_id=0x0001, vlan_id=5, vlan_priority=4)
    assert rt.encode_goose_frame(pdu, mac_to_bytes(DST), mac_to_bytes(SRC), 0x0001, 5, 4) == expected
    frame = goose.decode_goose_frame(expected)
    assert frame is not None and frame[1].all_data == all_data


def _refusals(pdu: goose.GoosePDU, **frame: int) -> tuple[bool, bool]:
    def python() -> None:
        goose.encode_goose_frame(pdu, dst_mac=DST, src_mac=SRC, app_id=1, **frame)  # type: ignore[arg-type]

    def native() -> None:
        rt.encode_goose_frame(pdu, mac_to_bytes(DST), mac_to_bytes(SRC), 1, frame.get("vlan_id"),
                              frame.get("vlan_priority"))

    refused = []
    for encode in (python, native):
        try:
            encode()
            refused.append(False)
        except ValueError:
            refused.append(True)
    return refused[0], refused[1]


def test_same_refusals() -> None:
    base = goose.GoosePDU("IED01LD0/LLN0$GO$gcb1", 2000, "IED01LD0/LLN0$DS1", None, EPOCH, 1, 0, False, 1, False, 1,
                          [BoolData(True)])
    bad_bits = goose.GoosePDU(**{**base.__dict__, "all_data": [StructureData([BitStringData(b"\x00", 8)])]})
    too_long = goose.GoosePDU(**{**base.__dict__, "all_data": [OctetStringData(bytes(0xFFFF))]})
    assert _refusals(base) == (False, False)
    assert _refusals(base, vlan_id=0xFFF, vlan_priority=7) == (False, False)
    assert _refusals(bad_bits) == (True, True)
    assert _refusals(base, vlan_id=0x1000) == (True, True)
    assert _refusals(base, vlan_id=1, vlan_priority=8) == (True, True)
    assert _refusals(too_long) == (True, True)

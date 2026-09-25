# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850-core's GOOSE decoder accepts what open61850.goose accepts, with the same fields.

Messages from the encoder, PDUs written TLV by TLV in forms the encoder
never uses (fields of any class and form, high tag numbers, repeated and
shuffled fields, counters with leading zeros or above 64 bits, short times,
odd Data: other constructed tags, IA5 strings, floats and times of other
sizes, INTEGERs beyond 64 bits, deep nesting), then byte mutations of all
of them: both decoders refuse, or both accept with the same values.
"""

from __future__ import annotations

import math
import random
import struct
from typing import Any, Optional

import pytest
from test_goose_encode_native import _data, _message
from test_sv_decode_native import _mutate, _tlv

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
    decode_binary_time,
    decode_utc_time,
    encode_data,
)
from open61850.ethernet import mac_to_str

rt = pytest.importorskip("open61850_rt")

I64 = range(-(2**63), 2**63)


def _flatten(values: list[IECData]) -> list[Any]:
    out: list[Any] = []
    for v in values:
        if isinstance(v, StructureData):
            out += [("struct", len(v.members))] + _flatten(v.members)
        elif isinstance(v, ArrayData):
            out += [("array", len(v.elements))] + _flatten(v.elements)
        else:
            out.append(v)
    return out


def _same_value(py: Any, rs: tuple) -> bool:
    kind = rs[0]
    if isinstance(py, tuple):
        return py == rs
    if isinstance(py, BoolData):
        return rs == ("bool", py.value)
    if isinstance(py, IntData):
        if kind == "raw":
            return rs[1] == 0x85 and py.value not in I64 and int.from_bytes(rs[2], "big", signed=True) == py.value
        return rs == ("int", py.value)
    if isinstance(py, UIntData):
        if kind == "raw":
            return rs[1] == 0x86 and py.value >> 64 != 0 and int.from_bytes(rs[2], "big") == py.value
        return rs == ("uint", py.value)
    if isinstance(py, FloatData):
        if kind == "f64" and py.double:
            return rs[1] == py.value or (math.isnan(rs[1]) and math.isnan(py.value))
        if kind == "f32" and not py.double:
            bits = rs[1].to_bytes(4, "big")
            return math.isnan(struct.unpack("!f", bits)[0]) if math.isnan(py.value) else struct.pack("!f", py.value) == bits
        return False
    if isinstance(py, BitStringData):
        return rs == ("bits", py.value, py.unused_bits)
    if isinstance(py, OctetStringData):
        return rs == ("octets", py.value)
    if isinstance(py, VisibleStringData):
        return kind == "visible" and rs[1].decode("ascii", errors="replace") == py.value
    if isinstance(py, MmsStringData):
        return kind == "mms" and rs[1].decode("utf-8", errors="replace") == py.value
    if isinstance(py, TimestampData):
        if kind == "utc":
            return decode_utc_time(rs[1]) == (py.value, py.quality)
        return kind == "btime" and (decode_binary_time(rs[1]), 0) == (py.value, py.quality)
    if isinstance(py, RawData):
        # Tags of more than four identifier octets read as u32::MAX.
        return kind == "raw" and rs[1] == min(py.tag, 0xFFFFFFFF) and rs[2] == py.value
    return False


def _same_pdu(py: goose.GoosePDU, rs: dict[str, Any]) -> None:
    def text(raw: Optional[bytes]) -> Optional[str]:
        return None if raw is None else raw.decode("ascii", errors="replace")

    assert (py.gocb_ref, py.time_allowed_to_live, py.dat_set, py.go_id, (py.timestamp, py.time_quality), py.st_num,
            py.sq_num, py.simulation, py.conf_rev, py.nds_com, py.num_dat_set_entries, len(py.all_data)) == (
        text(rs["gocb_ref"]), rs["time_allowed_to_live"], text(rs["dat_set"]), text(rs["go_id"]),
        decode_utc_time(rs["t"]), rs["st_num"], rs["sq_num"], rs["simulation"], rs["conf_rev"], rs["nds_com"],
        rs["num_dat_set_entries"], rs["entries"])
    expected = _flatten(py.all_data)
    assert len(expected) == len(rs["all_data"])
    for p, r in zip(expected, rs["all_data"]):
        assert _same_value(p, r), (p, r)


def _outcome(decode: Any, error: type[Exception], data: bytes) -> Any:
    try:
        return decode(data)
    except error as exc:
        return ("refused", str(exc))


def _compare_pdu(apdu: bytes) -> bool:
    py = _outcome(goose.decode_goose_pdu, goose.GooseDecodeError, apdu)
    rs = _outcome(rt.decode_goose_pdu, ValueError, apdu)
    py_ok, rs_ok = isinstance(py, goose.GoosePDU), isinstance(rs, dict)
    assert py_ok == rs_ok, f"{apdu.hex()}: Python {py!r}, native {rs!r}"
    if py_ok:
        _same_pdu(py, rs)
    return py_ok


def _compare_frame(raw: bytes) -> Optional[bool]:
    py = _outcome(goose.decode_goose_frame, goose.GooseDecodeError, raw)
    rs = _outcome(rt.decode_goose_frame, ValueError, raw)
    if py is None or rs is None:
        assert py is None and rs is None, f"{raw.hex()}: Python {py!r}, native {rs!r}"
        return None
    py_ok, rs_ok = py[0] != "refused", rs[0] != "refused"
    assert py_ok == rs_ok, f"{raw.hex()}: Python {py!r}, native {rs!r}"
    if py_ok:
        (frame, pdu), (header, native) = py, rs
        assert (frame.dst_mac, frame.src_mac, frame.vlan_id, frame.vlan_priority, frame.app_id, frame.reserved1,
                frame.reserved2) == (mac_to_str(header["dst_mac"]), mac_to_str(header["src_mac"]), header["vlan_id"],
                                     header["vlan_priority"], header["app_id"], header["reserved1"],
                                     header["reserved2"]), raw.hex()
        _same_pdu(pdu, native)
    return py_ok


def _field_tag(rng: random.Random, number: int) -> bytes:
    """Identifier octets of tag number ``number`` in some class and form."""
    if rng.random() < 0.1:
        return bytes([0x9F]) + b"\x80" * rng.randint(0, 5) + bytes([number])  # high form, padded
    return bytes([rng.choice([0x80, 0x80, 0x80, 0xA0, 0x00, 0x40, 0xC0]) | number])


def _counter(rng: random.Random) -> bytes:
    if rng.random() < 0.04:
        return rng.choice([b"", b"\x01" + bytes(8)])  # empty, above 64 bits: refused
    return rng.choice([b"\x05", b"\x00\x80", b"\x80", bytes(12) + b"\x01\x02", b"\xff" * 8, b"\x00" + b"\xff" * 8])


def _odd_data(rng: random.Random, depth: int = 0) -> bytes:
    choice = rng.randrange(12)
    if choice == 0 and depth < 60:
        inner = b"".join(_odd_data(rng, depth + 1) for _ in range(rng.choice([0, 1, 1, 2])))
        return _tlv(rng, rng.choice([b"\xa1", b"\xa2"]), inner)
    if choice == 1:
        return _tlv(rng, b"\xa3", encode_data(BoolData(True)))                   # other constructed tag
    if choice == 2:
        return _tlv(rng, rng.choice([b"\x1a", b"\x80"]), b"IED01")              # IA5 / [0] strings
    if choice == 3:
        return _tlv(rng, b"\x87", bytes(rng.choice([0, 3, 5, 9, 12])))         # floats of any size
    if choice == 4:
        return _tlv(rng, rng.choice([b"\x91", b"\x8c"]), bytes(rng.choice([0, 6, 7, 8, 9])))
    if choice == 5:
        return _tlv(rng, rng.choice([b"\x85", b"\x86"]), rng.choice([b"", b"\xff" * 12, b"\x00" * 9 + b"\x80",
                                                                      b"\x80" + bytes(8), b"\x01" + bytes(8)]))
    if choice == 6:
        return _tlv(rng, b"\x84", rng.choice([b"", b"\x03", b"\x07\x80"]))
    if choice == 7:
        return _tlv(rng, b"\x83", rng.choice([b"", b"\x00", b"\x01\x00", b"\x00\x01"]))
    if choice == 8:
        return _tlv(rng, rng.choice([b"\x9f\x20", b"\x1f\x81\x81\x81\x81\x01"]), b"\x00")
    if choice == 9:
        nested = encode_data(_data(rng))
        for _ in range(rng.randint(10, 80)):
            nested = _tlv(rng, rng.choice([b"\xa1", b"\xa2"]), nested)
        return nested
    return encode_data(_data(rng))


def _odd_pdu(rng: random.Random) -> bytes:
    values = {
        0: b"IED01LD0/LLN0$GO$gcb1", 1: _counter(rng), 2: b"IED01LD0/LLN0$DS1", 3: b"IED01_G1",
        4: bytes(rng.getrandbits(8) for _ in range(rng.choice([8, 8, 8, 8, 8, 10, 7]))),
        5: _counter(rng), 6: _counter(rng), 7: rng.choice([b"", b"\x00", b"\xff", b"\x00\x01"]),
        8: _counter(rng), 9: rng.choice([b"", b"\x01"]), 10: _counter(rng),
        11: b"".join(_odd_data(rng) for _ in range(rng.choice([0, 1, 3, 8]))),
    }
    fields = []
    for number, content in values.items():
        if rng.random() < 0.02:
            continue  # a missing field, mandatory or not
        tag = b"\xab" if number == 11 and rng.random() < 0.8 else _field_tag(rng, number)
        fields.append(_tlv(rng, tag, content))
        if rng.random() < 0.05:
            fields.append(_tlv(rng, _field_tag(rng, number), values[rng.randrange(12)]))  # repeated: last wins
    if rng.random() < 0.2:
        fields.append(_tlv(rng, _field_tag(rng, rng.choice([12, 20, 31])), b"\x00"))
    if rng.random() < 0.3:
        rng.shuffle(fields)
    return _tlv(rng, b"\x61", b"".join(fields)) + (b"\x00\x00" if rng.random() < 0.2 else b"")


@pytest.mark.parametrize("seed", range(20))
def test_pdu_parity(seed: int) -> None:
    rng = random.Random(seed)
    accepted = refused = 0
    for _ in range(100):
        apdu = goose.encode_goose_pdu(_message(rng)) if rng.random() < 0.4 else _odd_pdu(rng)
        _compare_pdu(apdu)
        for _ in range(10):
            if _compare_pdu(_mutate(rng, apdu)):
                accepted += 1
            else:
                refused += 1
    assert accepted > 50 and refused > 50  # the mutations exercise both outcomes


@pytest.mark.parametrize("seed", range(10))
def test_frame_parity(seed: int) -> None:
    rng = random.Random(2000 + seed)
    outcomes = set()
    for _ in range(100):
        vlan = rng.random() < 0.5
        raw = goose.encode_goose_frame(
            _message(rng), dst_mac="01:0c:cd:01:00:01", src_mac="02:00:00:00:00:01", app_id=rng.randint(0, 0xFFFF),
            vlan_id=rng.randint(0, 0xFFF) if vlan else None, vlan_priority=rng.randint(0, 7) if vlan else None,
        ) + bytes(rng.choice([0, 0, 4, 30]))
        assert _compare_frame(raw)
        for _ in range(10):
            mutated = _mutate(rng, raw[:30]) + raw[30:] if rng.random() < 0.5 else _mutate(rng, raw)
            outcomes.add(_compare_frame(mutated))
    assert outcomes == {None, True, False}


def test_deep_nesting() -> None:
    """Python recurses once per level; the native decoder does not recurse at all."""
    value: IECData = BoolData(True)
    for _ in range(200):
        value = StructureData([value])
    pdu = goose.GoosePDU("IED01LD0/LLN0$GO$gcb1", 2000, "IED01LD0/LLN0$DS1", None,
                         decode_utc_time(bytes(8))[0], 1, 0, False, 1, False, 1, [value])
    assert _compare_pdu(goose.encode_goose_pdu(pdu))

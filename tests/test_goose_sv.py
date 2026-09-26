# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for open61850.ethernet, open61850.goose and open61850.sv."""

from __future__ import annotations

import random
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional

import pytest
from conftest import ROOT

from open61850 import ber, ethernet, goose, sv
from open61850.capture import CapturedFrame
from open61850.data import BoolData, StructureData, UIntData
from open61850.supervision import BusSupervisor

# A 9-2LE style frame without its Ethernet header: 8-byte SV header, savPdu
# with 2 ASDUs (svID IED01_MU01_SV1, smpCnt 0x11B8 and 0x11B9, confRev 10000,
# smpSynch 2) and 64 bytes of zero samples each.
_ASDU = "305f800e" + b"IED01_MU01_SV1".hex() + "8202{:04x}8304000027108501028740" + "00" * 64
REF = bytes.fromhex("403000d3000000006081c8800102a281c2" + _ASDU.format(0x11B8) + _ASDU.format(0x11B9) + "00")


def test_library_imports_without_optional_dependencies() -> None:
    code = (
        "import sys\n"
        "sys.path.insert(0, 'src')\n"
        "import open61850.ber, open61850.data, open61850.ethernet, open61850.goose, open61850.sv\n"
        "import open61850.quality, open61850.scl, open61850.display, open61850.capture\n"
        "import open61850.pcap, open61850.supervision\n"
        "import open61850.mms, open61850.mms.rcb, open61850.mms.types, open61850.mms.control\n"
        "bad = {'scapy', 'pcapy', 'fastapi', 'flask'} & set(sys.modules)\n"
        "assert not bad, bad\n"
    )
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)


# --- ethernet ----------------------------------------------------------------


def test_frame_round_trip_with_vlan() -> None:
    raw = ethernet.build_frame(
        dst_mac="01:0c:cd:04:00:01", src_mac="00:02:a3:00:00:01", ethertype=ethernet.ETHERTYPE_SV,
        app_id=0x4000, apdu=b"\x60\x00", vlan_id=100, vlan_priority=4,
    )
    frame = ethernet.parse_frame(raw + bytes(30))  # trailing Ethernet padding is ignored
    assert frame == ethernet.EthernetFrame(
        dst_mac="01:0c:cd:04:00:01", src_mac="00:02:a3:00:00:01", vlan_id=100, vlan_priority=4,
        ethertype=ethernet.ETHERTYPE_SV, app_id=0x4000, reserved1=0, reserved2=0, apdu=b"\x60\x00",
    )


@pytest.mark.parametrize("cut", [0, 13, 17, 21])
def test_truncated_frames_are_ignored(cut: int) -> None:
    raw = ethernet.build_frame(
        dst_mac="01:0c:cd:04:00:01", src_mac="00:02:a3:00:00:01", ethertype=ethernet.ETHERTYPE_GOOSE,
        app_id=1, apdu=b"\x61\x00", vlan_id=1,
    )
    assert ethernet.parse_frame(raw[:cut]) is None


def test_inconsistent_length_is_ignored() -> None:
    raw = bytearray(ethernet.build_frame(
        dst_mac="01:0c:cd:04:00:01", src_mac="00:02:a3:00:00:01", ethertype=ethernet.ETHERTYPE_GOOSE,
        app_id=1, apdu=b"\x61\x00",
    ))
    raw[16:18] = (100).to_bytes(2, "big")
    assert ethernet.parse_frame(bytes(raw)) is None


# --- GOOSE -------------------------------------------------------------------


def _goose_pdu() -> goose.GoosePDU:
    return goose.GoosePDU(
        gocb_ref="IED1LD0/LLN0$GO$gcb1", time_allowed_to_live=2000, dat_set="IED1LD0/LLN0$DS1",
        go_id=None, timestamp=datetime(2026, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc),
        st_num=2**31, sq_num=0, simulation=True, conf_rev=1, nds_com=False, num_dat_set_entries=2,
        all_data=[BoolData(True), UIntData(200)], time_quality=0x0A,
    )


def test_goose_frame_round_trip() -> None:
    raw = goose.encode_goose_frame(
        _goose_pdu(), dst_mac="01:0c:cd:01:00:01", src_mac="00:02:a3:00:00:01", app_id=3, vlan_id=0,
    )
    frame, pdu = goose.decode_goose_frame(raw)  # type: ignore[misc]
    assert frame.app_id == 3 and frame.vlan_id == 0
    assert pdu == _goose_pdu()


def test_goose_rejects_missing_mandatory_field() -> None:
    apdu = goose.encode_goose_pdu(_goose_pdu())
    # Drop the stNum TLV (tag 0x85).
    fields = b"".join(
        goose.ber.encode_tlv(t.tag, t.value)
        for t in goose.ber.iter_tlvs(goose.ber.decode_tlv(apdu).value)
        if t.tag != 0x85
    )
    with pytest.raises(goose.GooseDecodeError, match=r"missing mandatory GOOSE fields \[5\]"):
        goose.decode_goose_pdu(goose.ber.encode_tlv(0x61, fields))


def test_goose_empty_data_set_keeps_all_data() -> None:
    # allData [11] is not OPTIONAL in IEC 61850-8-1 (libiec61850 writes it too).
    pdu = goose.GoosePDU(**{**_goose_pdu().__dict__, "all_data": [], "num_dat_set_entries": 0})
    apdu = goose.encode_goose_pdu(pdu)
    assert apdu.endswith(b"\x8a\x01\x00\xab\x00")
    assert goose.decode_goose_pdu(apdu).all_data == []


def test_goose_counters_stop_at_64_bits() -> None:
    apdu = goose.encode_goose_pdu(_goose_pdu())
    fields = list(goose.ber.iter_tlvs(goose.ber.decode_tlv(apdu).value))

    def with_st_num(content: bytes) -> bytes:
        return goose.ber.encode_tlv(0x61, b"".join(
            goose.ber.encode_tlv(t.tag, content if t.tag == 0x85 else t.value) for t in fields))

    assert goose.decode_goose_pdu(with_st_num(bytes(12) + b"\xff" * 8)).st_num == 2**64 - 1
    with pytest.raises(goose.GooseDecodeError, match="stNum above 64 bits"):
        goose.decode_goose_pdu(with_st_num(b"\x01" + bytes(8)))


def _goose_fields(**replace: bytes) -> list[bytes]:
    """The TLVs of _goose_pdu()'s PDU, some replaced by tag."""
    apdu = goose.encode_goose_pdu(_goose_pdu())
    return [replace.get(f"t{t.tag:02x}", goose.ber.encode_tlv(t.tag, t.value))
            for t in goose.ber.iter_tlvs(goose.ber.decode_tlv(apdu).value)]


def _strict(fields: list[bytes], after: bytes = b"") -> Optional[str]:
    """None when the strict decoder accepts the PDU, else its refusal."""
    apdu = goose.ber.encode_tlv(0x61, b"".join(fields)) + after
    goose.decode_goose_pdu(apdu)  # the lenient decoder accepts them all
    try:
        goose.decode_goose_pdu(apdu, strict=True)
        return None
    except goose.GooseDecodeError as exc:
        return str(exc)


def test_goose_strict_accepts_a_conformant_message() -> None:
    assert _strict(_goose_fields()) is None
    without_simulation = [f for f in _goose_fields() if f[0] != 0x87]
    assert _strict(without_simulation) is None  # simulation is DEFAULT FALSE: may be absent
    assert _strict(_goose_fields(t85=b"\x85\x05\x00\xff\xff\xff\xff")) is None  # 2^32 - 1
    deep = goose.encode_goose_pdu(goose.GoosePDU(**{**_goose_pdu().__dict__, "num_dat_set_entries": 1,
                                                   "all_data": [_nested(50)]}))
    assert goose.decode_goose_pdu(deep, strict=True).num_dat_set_entries == 1


def _nested(depth: int) -> StructureData:
    value = StructureData([BoolData(True)])
    for _ in range(depth - 1):
        value = StructureData([value])
    return value


@pytest.mark.parametrize("replace, after, reason", [
    ({}, b"\x00", "octets after the PDU"),
    ({"t80": b"\xa0\x01A"}, b"", "not a GOOSE field"),
    ({"t80": b"\x80\x00"}, b"", "empty gocbRef"),
    ({"t80": b"\x80\x03IE\x01"}, b"", "gocbRef is not a VisibleString129"),
    ({"t82": b"\x82\x82\x00\x82" + b"A" * 130}, b"", "datSet is not a VisibleString129"),
    ({"t84": b"\x84\x09" + bytes(9)}, b"", "t of 9 octets"),
    ({"t85": b"\x85\x05\x01\x00\x00\x00\x00"}, b"", "stNum above 32 bits"),
    ({"t87": b"\x87\x02\x00\x01"}, b"", "simulation of 2 octets"),
    ({"t8a": b"\x8a\x01\x03"}, b"", "numDatSetEntries=3 but 2 entries"),
    ({"tab": b"\xab\x04\x83\x00\x86\x00"}, b"", "allData value 0x83 of 0 octets"),
    ({"tab": b"\xab\x05\xa9\x00\x86\x01\x01"}, b"", "allData tag 0xA9 is not a Data"),
    ({"tab": b"\xab\x05\x82\x00\x86\x01\x01"}, b"", "allData tag 0x82 is not a Data"),
    ({"tab": b"\xab\x06\x87\x01\x08\x86\x01\x01"}, b"", "allData value 0x87 of 1 octets"),
])
def test_goose_strict_refuses_what_8_1_does_not_allow(replace: dict, after: bytes, reason: str) -> None:
    refusal = _strict(_goose_fields(**replace), after)
    assert refusal is not None and reason in refusal, refusal


def test_goose_strict_refuses_fields_out_of_order() -> None:
    fields = _goose_fields()
    t, st_num = fields.index(_goose_fields()[3]), 4
    assert fields[t][0] == 0x84 and fields[st_num][0] == 0x85
    fields[t], fields[st_num] = fields[st_num], fields[t]
    assert "field [4] after [5]" in (_strict(fields) or "")


def test_goose_rejects_garbage() -> None:
    with pytest.raises(goose.GooseDecodeError):
        goose.decode_goose_pdu(b"\x61\x05\x80\x01")


def test_goose_frame_of_other_ethertype_is_none() -> None:
    raw = ethernet.build_frame(
        dst_mac="01:0c:cd:04:00:01", src_mac="00:02:a3:00:00:01", ethertype=ethernet.ETHERTYPE_SV,
        app_id=1, apdu=b"\x60\x00",
    )
    assert goose.decode_goose_frame(raw) is None


# --- SV ----------------------------------------------------------------------


def test_sv_reference_packet() -> None:
    pdu = sv.decode_sv_pdu(REF[8:])
    assert [(a.sv_id, a.smp_cnt, a.conf_rev, a.smp_synch) for a in pdu.asdus] == [
        ("IED01_MU01_SV1", 0x11B8, 10000, 2),
        ("IED01_MU01_SV1", 0x11B9, 10000, 2),
    ]
    assert sv.decode_int32_samples(pdu.asdus[0].sample) == [(0, 0)] * 8


def test_sv_optional_fields_round_trip() -> None:
    asdu = sv.SvAsdu(
        sv_id="MU01", dat_set="MU01LD0/LLN0$PhsMeas1", smp_cnt=3999, conf_rev=1, smp_synch=sv.SMP_SYNCH_GLOBAL,
        sample=sv.encode_int32_samples([(0, 0)] * 9), refr_tm=datetime(2026, 1, 1, tzinfo=timezone.utc),
        smp_rate=4000, smp_mod=0, gm_identity=bytes(range(8)),
    )
    assert sv.decode_sv_pdu(sv.encode_sv_pdu(sv.SvPDU([asdu]))).asdus == [asdu]


def test_sv_no_asdu_mismatch() -> None:
    apdu = bytearray(sv.encode_sv_pdu(sv.SvPDU([sv.SvAsdu("X", 0, 1, 0, b"")])))
    apdu[4] = 2  # noASDU says 2, one ASDU present
    with pytest.raises(sv.SvDecodeError, match="noASDU=2"):
        sv.decode_sv_pdu(bytes(apdu))


def test_sv_long_sample_uses_the_long_length_form() -> None:
    # 16 channels = 128 bytes: seqData needs 81 80, outside the short-length fast path.
    values = [(i, 0) for i in range(16)]
    asdu = sv.SvAsdu("SV_16", 1, 1, 2, sv.encode_int32_samples(values), smp_rate=4800)
    raw = sv.encode_sv_pdu(sv.SvPDU([asdu]))
    assert bytes.fromhex("878180") in raw
    (decoded,) = sv.decode_sv_pdu(raw).asdus
    assert decoded == asdu and sv.decode_int32_samples(decoded.sample) == values
    with pytest.raises(sv.SvDecodeError):
        sv.decode_sv_pdu(raw[:-3])


# --- hostile input -------------------------------------------------------------


def _mutants(frame: bytes, count: int, seed: int) -> list[bytes]:
    """Reproducible corruptions: a few bytes overwritten, and one in five truncated."""
    rng = random.Random(seed)
    out = []
    for _ in range(count):
        raw = bytearray(frame)
        for _ in range(rng.choice((1, 1, 2, 3))):
            raw[rng.randrange(len(raw))] = rng.randrange(256)
        if rng.random() < 0.2:
            raw = raw[: rng.randrange(len(raw))]
        out.append(bytes(raw))
    return out


def test_corrupted_frames_raise_only_ber_errors() -> None:
    goose_frame = goose.encode_goose_frame(
        _goose_pdu(), dst_mac="01:0c:cd:01:00:01", src_mac="02:00:00:00:00:01", app_id=1, vlan_id=10,
    )
    asdu = sv.SvAsdu("MU01", 12, 1, 2, sv.encode_int32_samples([(i, 0) for i in range(8)]), smp_rate=4000)
    sv_frame = sv.encode_sv_frame(sv.SvPDU([asdu, asdu]), dst_mac="01:0c:cd:04:00:01", src_mac="02:00:00:00:00:02",
                                  app_id=0x4000)
    bus = BusSupervisor()
    for frame, decode in ((goose_frame, goose.decode_goose_frame), (sv_frame, sv.decode_sv_frame)):
        for raw in _mutants(frame, 3000, seed=61850):
            try:
                decode(raw)
            except ber.BerError:
                pass
            bus.feed(CapturedFrame(0.0, raw, False))  # never raises

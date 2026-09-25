# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for open61850.ethernet, open61850.goose and open61850.sv."""

from __future__ import annotations

import random
import subprocess
import sys
from datetime import datetime, timezone

import pytest
from conftest import ROOT

from open61850 import ber, ethernet, goose, sv
from open61850.capture import CapturedFrame
from open61850.data import BoolData, UIntData
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

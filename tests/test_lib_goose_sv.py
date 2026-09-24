# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for iec61850.ethernet, iec61850.goose and iec61850.sv."""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone

import pytest
from conftest import ROOT
from test_sv import _asdu, _seq_data_6i3u, _sv_payload

from iec61850 import ethernet, goose, sv
from iec61850.data import BoolData, UIntData
from parse_ref_pkt import REF


def test_library_imports_without_optional_dependencies() -> None:
    code = (
        "import sys\n"
        "import iec61850.ber, iec61850.data, iec61850.ethernet, iec61850.goose, iec61850.sv\n"
        "import iec61850.quality, iec61850.mms, iec61850.mms.rcb, iec61850.mms.types\n"
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


def test_sv_encoder_matches_rt_sender_layout() -> None:
    samples = [(1000, 0), (-500, 0x2000), (-500, 0), (0, 0), (0, 0), (0, 0), (10000, 0), (-5000, 0), (-5000, 0)]
    asdus = [
        sv.SvAsdu(sv_id="SV_1", smp_cnt=n, conf_rev=10000, smp_synch=2, sample=sv.encode_int32_samples(samples))
        for n in (0, 1)
    ]
    expected = _sv_payload(0x4060, [_asdu("SV_1", n, 10000, 2, sv.encode_int32_samples(samples)) for n in (0, 1)])
    raw = sv.encode_sv_frame(sv.SvPDU(asdus), dst_mac="01:0c:cd:04:00:01", src_mac="00:00:00:00:00:01", app_id=0x4060)
    assert raw[14:] == expected
    frame, pdu = sv.decode_sv_frame(raw)  # type: ignore[misc]
    assert pdu.asdus == asdus
    assert sv.decode_int32_samples(pdu.asdus[0].sample)[1] == (-500, 0x2000)


def test_sv_optional_fields_round_trip() -> None:
    asdu = sv.SvAsdu(
        sv_id="MU01", dat_set="MU01LD0/LLN0$PhsMeas1", smp_cnt=3999, conf_rev=1, smp_synch=sv.SMP_SYNCH_GLOBAL,
        sample=_seq_data_6i3u([0] * 9), refr_tm=datetime(2026, 1, 1, tzinfo=timezone.utc),
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

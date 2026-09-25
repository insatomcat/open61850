# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for open61850.supervision."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone

import pytest
from conftest import DATA_DIR

from open61850 import goose, sv
from open61850.capture import CapturedFrame
from open61850.data import BoolData, FloatData
from open61850.supervision import BusSupervisor, EventKind, GooseSupervisor, SvSupervisor, main

K = EventKind
REF = "IED01_LD0/LLN0$GO$gcb1"


def _goose(st: int, sq: int, *values: bool, **changes) -> goose.GoosePDU:
    data = [BoolData(v) for v in (values or (False,))]
    pdu = goose.GoosePDU(REF, 2000, "IED01_LD0/LLN0$DS1", "G1", datetime(2026, 9, 25, tzinfo=timezone.utc),
                         st, sq, False, 1, False, len(data), data)
    return dataclasses.replace(pdu, **changes)


def _kinds(events) -> list[EventKind]:
    return [e.kind for e in events]


def test_goose_retransmissions_are_quiet_and_state_changes_reported() -> None:
    sup = GooseSupervisor()
    assert _kinds(sup.feed(_goose(1, 0), 0.0)) == [K.NEW_STREAM]
    assert sup.feed(_goose(1, 1), 0.002) == []
    assert sup.feed(_goose(1, 2), 0.010) == []
    (event,) = sup.feed(_goose(2, 0, True), 0.5)
    assert (event.kind, event.missed, event.stream) == (K.STATE_CHANGE, 0, REF)
    assert "entries [0]" in event.detail
    (event,) = sup.feed(_goose(5, 0, False), 0.6)
    assert (event.kind, event.missed) == (K.STATE_CHANGE, 2)
    stream = sup.streams[REF]
    assert (stream.messages, stream.missed, stream.events[K.STATE_CHANGE]) == (5, 2, 2)


def test_goose_sequence_anomalies() -> None:
    sup = GooseSupervisor()
    sup.feed(_goose(3, 4), 0.0)
    (gap,) = sup.feed(_goose(3, 8), 0.1)
    assert (gap.kind, gap.missed) == (K.GAP, 3)
    assert _kinds(sup.feed(_goose(3, 8), 0.2)) == [K.DUPLICATE]
    assert _kinds(sup.feed(_goose(3, 6), 0.3)) == [K.OUT_OF_ORDER]  # late: no longer missed
    assert _kinds(sup.feed(_goose(3, 6), 0.3)) == [K.DUPLICATE]
    assert _kinds(sup.feed(_goose(3, 4), 0.3)) == [K.DUPLICATE]
    assert sup.feed(_goose(3, 9), 0.4) == []  # the late ones did not move the reference
    assert sup.streams[REF].missed == 2
    sup.feed(_goose(4, 0, True), 0.5)
    assert _kinds(sup.feed(_goose(4, 2, True), 0.6)) == [K.GAP]
    assert _kinds(sup.feed(_goose(4, 1, True), 0.6)) == [K.OUT_OF_ORDER]  # sqNum 1 of the old state is forgotten


def test_goose_restart_is_followed_at_once() -> None:
    """An IED that restarts sends stNum 1 again: the stream must be followed from there."""
    sup = GooseSupervisor()
    sup.feed(_goose(40, 0), 0.0)
    sup.feed(_goose(40, 1), 0.1)
    assert _kinds(sup.feed(_goose(1, 0), 5.0)) == [K.RESTART]
    assert sup.feed(_goose(1, 1), 5.1) == []
    assert _kinds(sup.feed(_goose(2, 0, True), 5.2)) == [K.STATE_CHANGE]


def test_goose_counter_wraps() -> None:
    sup = GooseSupervisor()
    sup.feed(_goose(0xFFFFFFFF, 0xFFFFFFFF), 0.0)
    assert sup.feed(_goose(0xFFFFFFFF, 1), 0.1) == []
    assert _kinds(sup.feed(_goose(1, 0, True), 0.2)) == [K.STATE_CHANGE]


def test_goose_time_allowed_to_live() -> None:
    sup = GooseSupervisor()
    sup.feed(_goose(1, 0), 10.0)
    assert sup.check(11.9) == []
    (timeout,) = sup.check(12.1)
    assert timeout.kind is K.TIMEOUT and "TAL 2000 ms" in timeout.detail
    assert sup.check(13.0) == []  # once per silence
    assert _kinds(sup.feed(_goose(1, 1), 14.0)) == [K.RESUMED]
    assert sup.check(15.0) == []


def test_goose_configuration_and_flags() -> None:
    sup = GooseSupervisor()
    assert _kinds(sup.feed(_goose(1, 0, simulation=True), 0.0)) == [K.NEW_STREAM, K.SIMULATION]
    events = sup.feed(_goose(1, 1, conf_rev=2, nds_com=True), 0.1)
    assert _kinds(events) == [K.CONFIG_CHANGED, K.SIMULATION, K.NDS_COM]
    assert events[0].detail == "confRev 1 -> 2"
    assert events[1].detail == "simulation bit cleared"


def test_goose_data_change_without_new_state() -> None:
    sup = GooseSupervisor()
    sup.feed(_goose(1, 0, False, False), 0.0)
    (event,) = sup.feed(_goose(1, 1, False, True), 0.1)
    assert event.kind is K.DATA_WITHOUT_STATE_CHANGE and "entries [1]" in event.detail


def test_goose_nan_is_not_a_data_change() -> None:
    sup = GooseSupervisor()
    nan = [FloatData(float("nan"))]
    sup.feed(_goose(1, 0, all_data=nan, num_dat_set_entries=1), 0.0)
    assert sup.feed(_goose(1, 1, all_data=[FloatData(float("nan"))], num_dat_set_entries=1), 0.1) == []


def test_goose_inconsistent_entry_count_reported_once() -> None:
    sup = GooseSupervisor()
    assert _kinds(sup.feed(_goose(1, 0, num_dat_set_entries=3), 0.0)) == [K.NEW_STREAM, K.INCONSISTENT]
    assert sup.feed(_goose(1, 1, num_dat_set_entries=3), 0.1) == []


# --- Sampled Values ------------------------------------------------------------


def _sv(*counts: int, sv_id: str = "MU01", **fields) -> sv.SvPDU:
    return sv.SvPDU([sv.SvAsdu(sv_id=sv_id, smp_cnt=c, conf_rev=1, smp_synch=2, sample=b"", **fields) for c in counts])


def _run(sup: SvSupervisor, counts: list[int], sv_id: str = "MU01") -> list:
    events = []
    for i, c in enumerate(counts):
        events += sup.feed(_sv(c, sv_id=sv_id), i * 0.00025)
    return events


def test_sv_continuous_stream_with_known_rate() -> None:
    sup = SvSupervisor(4000)
    events = _run(sup, [3997, 3998, 3999, 0, 1, 2])
    assert _kinds(events) == [K.NEW_STREAM]
    assert sup.streams["MU01"].samples == 6


@pytest.mark.parametrize("counts, missed", [
    ([10, 11, 15], 3),
    ([3997, 3998, 0], 1),  # 3999 lost at the wrap, a loss seen on real captures
    ([3998, 2], 3),
])
def test_sv_gaps(counts: list[int], missed: int) -> None:
    sup = SvSupervisor(4000)
    (gap,) = _run(sup, counts)[1:]
    assert (gap.kind, gap.missed) == (K.GAP, missed)
    assert sup.streams["MU01"].missed == missed


def test_sv_duplicate_out_of_order_and_restart() -> None:
    sup = SvSupervisor(4000)
    events = _run(sup, [100, 101, 101, 99, 102, 1000, 1001])
    assert _kinds(events) == [K.NEW_STREAM, K.DUPLICATE, K.OUT_OF_ORDER, K.GAP]
    assert _kinds(_run(sup, [0, 1, 2])) == [K.RESTART]  # back, far from a wrap
    assert _kinds(_run(sup, [3000, 3001])) == [K.RESTART]  # forward by more than half a second


def test_sv_duplicate_frame_and_late_samples() -> None:
    sup = SvSupervisor(4000)
    events = _run(sup, [3998, 3999, 0, 1, 0, 1, 2, 5, 3, 4, 6])
    assert [(e.kind, e.detail) for e in events[1:]] == [
        (K.DUPLICATE, "smpCnt 0"), (K.DUPLICATE, "smpCnt 1"),
        (K.GAP, "smpCnt 2 -> 5"), (K.OUT_OF_ORDER, "smpCnt 3 after 5"), (K.OUT_OF_ORDER, "smpCnt 4 after 5"),
    ]
    assert sup.streams["MU01"].missed == 0
    assert _kinds(_run(sup, [3999])) == [K.DUPLICATE]  # behind across the wrap


def test_sv_rate_learnt_from_the_first_wrap() -> None:
    sup = SvSupervisor()
    counts = list(range(4790, 4800)) + list(range(0, 4800)) + [0, 1, 3]
    events = _run(sup, counts)
    # 4790..4799 then 0: the first wrap is taken as clean; the rate is 4800 from then on.
    assert _kinds(events) == [K.NEW_STREAM, K.GAP]
    assert sup.wrap(sup.streams["MU01"], _sv(0).asdus[0]) == 4800
    events = _run(sup, list(range(3000, 4799)) + [1])
    assert [(e.kind, e.missed) for e in events] == [(K.RESTART, 0), (K.GAP, 2)]
    assert sup.streams["MU01"].missed == 1 + 2


def test_sv_rate_from_smp_rate_and_smp_mod() -> None:
    sup = SvSupervisor()
    for i, c in enumerate([4797, 4798, 0]):
        events = sup.feed(_sv(c, smp_rate=4800, smp_mod=1), i)
    assert [(e.kind, e.missed) for e in events] == [(K.GAP, 1)]


def test_sv_several_asdus_and_streams() -> None:
    sup = SvSupervisor(4000)
    assert _kinds(sup.feed(_sv(1, 2), 0.0)) == [K.NEW_STREAM]
    assert _kinds(sup.feed(_sv(3, 5), 0.001)) == [K.GAP]
    assert _kinds(sup.feed(_sv(1, sv_id="MU02"), 0.001)) == [K.NEW_STREAM]
    assert sorted(sup.streams) == ["MU01", "MU02"]
    assert sup.streams["MU01"].samples == 4


def test_sv_synch_config_and_timeout() -> None:
    sup = SvSupervisor(4000, timeout=0.05)
    sup.feed(_sv(1), 0.0)
    events = sup.feed(sv.SvPDU([sv.SvAsdu("MU01", 2, 3, 0, b"")]), 0.001)
    assert [e.detail for e in events] == ["confRev 1 -> 3", "smpSynch 2 -> 0"]
    assert sup.check(0.04) == []
    assert _kinds(sup.check(0.06)) == [K.TIMEOUT]
    assert _kinds(sup.feed(sv.SvPDU([sv.SvAsdu("MU01", 3, 3, 0, b"")]), 0.5)) == [K.RESUMED]
    assert SvSupervisor(timeout=None).check(1e9) == []


# --- Raw frames, files, command line -------------------------------------------


def test_bus_supervisor_on_frames() -> None:
    bus = BusSupervisor(sv_supervisor=SvSupervisor(4000))
    goose_frame = goose.encode_goose_frame(_goose(1, 0), dst_mac="01:0c:cd:01:00:01", src_mac="02:00:00:00:00:01", app_id=1)
    sv_frame = sv.encode_sv_frame(_sv(7), dst_mac="01:0c:cd:04:00:01", src_mac="02:00:00:00:00:02", app_id=0x4000)
    assert _kinds(bus.feed(CapturedFrame(0.0, goose_frame, False))) == [K.NEW_STREAM]
    assert _kinds(bus.feed(CapturedFrame(0.0, sv_frame, False))) == [K.NEW_STREAM]
    assert bus.feed(CapturedFrame(0.0, sv_frame[:30], False)) == []
    assert bus.feed(CapturedFrame(0.0, goose_frame[:-3], False)) == []
    assert bus.feed(CapturedFrame(0.0, bytes(60), False)) == []
    assert _kinds(bus.feed(CapturedFrame(3.0, sv_frame, False))) == [K.TIMEOUT, K.TIMEOUT, K.RESUMED, K.DUPLICATE]
    assert bus.frames == {"goose": 2, "sv": 3, "other": 1}
    assert bus.malformed == {"goose": 1, "sv": 1}
    summary = bus.summary()
    assert summary[0].startswith(f"GOOSE {REF} APPID 0x0001 from 02:00:00:00:00:01: 1 messages")
    assert summary[1].startswith("SV MU01 APPID 0x4000 from 02:00:00:00:00:02: 2 samples")
    assert summary[-1] == "frames: 2 goose, 1 other, 3 sv; malformed: 1 goose, 1 sv"


def test_command_line_on_a_file(tmp_path, capsys) -> None:
    path = tmp_path / "bus.pcapng"
    path.write_bytes(bytes.fromhex(json.loads((DATA_DIR / "editcap_pcapng.json").read_text())["ns"]))
    assert main([str(path), "--events", "--sample-rate", "4000"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "1790000000.123457 MU01 new stream: smpCnt 0, confRev 1, smpSynch 2"
    assert out[1] == "1790000000.500000 MU01 timeout: nothing for 0.376 s"
    assert out[2].endswith(f"{REF} new stream: stNum 3 sqNum 7, TAL 2000 ms")
    assert out[3].startswith(f"GOOSE {REF} APPID 0x0001")
    assert out[4].startswith("SV MU01 APPID 0x4000 from 02:00:00:00:00:02: 5 samples, 4000 samples/s, 0 missed (1 timeout)")
    assert out[5] == "frames: 1 goose, 5 sv"


def test_command_line_reports_a_bad_file(tmp_path, capsys) -> None:
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"nope")
    assert main([str(bad)]) == 1
    captured = capsys.readouterr()
    assert "not a pcap" in captured.err
    assert captured.out == "frames: none\n"

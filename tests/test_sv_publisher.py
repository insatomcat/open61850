# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850.sv_publisher: templates, waveforms, faults, and the Python engine on lo."""

from __future__ import annotations

import math
import socket
import sys
import time
from fractions import Fraction

import pytest

from open61850 import sv
from open61850.sv_publisher import (
    SIMULATION_BIT,
    Fault,
    Playback,
    Publisher,
    SvStream,
    Wave,
    build_template,
    render_frame,
    sample_values,
    three_phase,
)

RATE = 4800


def _stream(**kwargs: object) -> SvStream:
    base = dict(sv_id="IED01_MU01_SV1", app_id=0x4000, dst_mac="01:0c:cd:04:00:01", src_mac="02:00:00:00:00:01",
                waves=three_phase(i_peak=10, v_peak=100), conf_rev=10000, smp_synch=sv.SMP_SYNCH_GLOBAL)
    base.update(kwargs)
    return SvStream(**base)  # type: ignore[arg-type]


def test_rendered_frames_decode() -> None:
    stream = _stream(vlan_id=100, vlan_priority=4, dat_set="IED01MU01/LLN0$PhsMeas1")
    template = build_template(stream, 2, RATE)
    raw = render_frame(template, stream, 1_790_000_000, 4798, RATE)  # crosses the second
    frame, pdu = sv.decode_sv_frame(raw)  # type: ignore[misc]
    assert frame.vlan_id == 100 and frame.app_id == 0x4000
    assert [(a.sv_id, a.smp_cnt, a.conf_rev, a.smp_synch, a.dat_set) for a in pdu.asdus] == [
        ("IED01_MU01_SV1", 4798, 10000, 2, "IED01MU01/LLN0$PhsMeas1"),
        ("IED01_MU01_SV1", 4799, 10000, 2, "IED01MU01/LLN0$PhsMeas1"),
    ]
    assert [v for v, _q in sv.decode_int32_samples(pdu.asdus[0].sample)] == sample_values(stream, 1_790_000_000, 4798, RATE)
    assert [v for v, _q in sv.decode_int32_samples(pdu.asdus[1].sample)] == sample_values(stream, 1_790_000_000, 4799, RATE)


def test_next_second_starts_at_smp_cnt_zero() -> None:
    stream = _stream()
    template = build_template(stream, 4, RATE)
    raw = render_frame(template, stream, 1_790_000_000, 4798, RATE)
    _frame, pdu = sv.decode_sv_frame(raw)  # type: ignore[misc]
    assert [a.smp_cnt for a in pdu.asdus] == [4798, 4799, 0, 1]
    assert [v for v, _q in sv.decode_int32_samples(pdu.asdus[2].sample)] == sample_values(stream, 1_790_000_001, 0, RATE)


def test_simulation_bit_and_template_checks() -> None:
    raw = build_template(_stream(simulation=True), 1, RATE).frame
    assert int.from_bytes(raw[18:20], "big") & SIMULATION_BIT
    with pytest.raises(ValueError):
        build_template(_stream(), 0, RATE)
    with pytest.raises(ValueError):
        build_template(_stream(fault=Fault(waves=(Wave(),), cycle_s=4)), 2, RATE)


# --- the rt_sender formulas, as PO's generator computes them -----------------


def _rt_sender_6i3u(smp: int, freq: float, i_peak: float, v_peak: float, lag: float,
                    fault: bool, fi: float, fv: float, fphase: float) -> list[int]:
    t = smp / RATE
    phase = 2 * math.pi * freq * t
    ia = (fi if fault else i_peak) * math.sin(phase - math.radians(fphase if fault else lag))
    ib = i_peak * math.sin(phase - math.radians(lag) - 2 * math.pi / 3)
    ic = i_peak * math.sin(phase - math.radians(lag) - 4 * math.pi / 3)
    va = (fv if fault else v_peak) * math.sin(phase)
    vb = v_peak * math.sin(phase - 2 * math.pi / 3)
    vc = v_peak * math.sin(phase - 4 * math.pi / 3)
    return [round(ia * 1000), round(ib * 1000), round(ic * 1000), round((ia + ib + ic) * 1000), 0, 0,
            round(va * 100), round(vb * 100), round(vc * 100)]


def _rt_sender_in_fault(sec: int, smp: int, cycle: int, offset: int, fault_smp: int) -> bool:
    period = cycle * RATE
    phase = (offset % cycle) * RATE + fault_smp
    return (sec * RATE + smp - phase) % period < period // 2


@pytest.mark.parametrize("smp", [0, 1, 17, 1200, 2401, 4799])
def test_values_match_rt_sender(smp: int) -> None:
    normal = three_phase(i_peak=10, v_peak=100, i_lag_deg=30)
    faulty = three_phase(i_peak=10, v_peak=100, i_lag_deg=30, ia_peak=50, ia_lag_deg=80, va_peak=20)
    for fault, waves in ((False, normal), (True, faulty)):
        ours = [w.value(1_790_000_000, smp, RATE) for w in waves]
        theirs = _rt_sender_6i3u(smp, 50, 10, 100, 30, fault, 50, 20, 80)
        assert ours[:3] + ours[4:] == theirs[:3] + theirs[4:]
        assert abs(ours[3] - theirs[3]) <= 1  # Ires: one rounding instead of three


def test_fault_schedule_matches_rt_sender() -> None:
    fault = Fault(waves=three_phase(i_peak=50, v_peak=20), cycle_s=4, offset_s=1, start_smp=24)
    for sec in range(1_790_000_000, 1_790_000_009):
        for smp in (0, 23, 24, 25, 2400, 4799):
            assert fault.active(sec, smp, RATE) == _rt_sender_in_fault(sec, smp, 4, 1, 24)
    assert not Fault(waves=(), cycle_s=4, duration_s=0).active(1_790_000_000, 0, RATE)


def test_phase_is_continuous_across_seconds_at_any_frequency() -> None:
    wave = Wave(amplitude=1.0, freq_hz=49.5, scale=1_000_000)
    for second in (0, 1_790_000_000, 1_790_000_001):
        for smp in (0, RATE - 1):
            cycles = Fraction(99, 2) * (second * RATE + smp) / RATE
            exact = math.sin(2 * math.pi * float(cycles % 1))
            assert wave.value(second, smp, RATE) == round(exact * 1_000_000)


def test_four_i_four_u_layout() -> None:
    waves = three_phase(i_peak=10, v_peak=100, layout="4I4U")
    assert len(waves) == 8 and waves[3].amplitude < 1e-6 and waves[7].amplitude < 1e-6
    with pytest.raises(ValueError):
        three_phase(i_peak=1, v_peak=1, layout="7I")


def test_publisher_configuration() -> None:
    with pytest.raises(ValueError):
        Publisher("lo", rate=4800, asdus_per_frame=7)
    with pytest.raises(ValueError):
        Publisher("lo", engine="gpu")
    with pytest.raises(ValueError):
        Publisher("lo", engine="python").start()
    assert Publisher("lo", engine="python").stats().frames_sent == 0


# --- the Python engine on lo (Linux, root) -----------------------------------

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET is Linux only")


@linux_only
def test_python_engine_sends_every_sample_on_time() -> None:
    from open61850.capture import PacketCapture

    try:
        cap = PacketCapture("lo", (0x88BA,), timeout=0.05, outgoing=False)
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    rate = 400  # low enough for a Python thread
    stream = _stream(waves=three_phase(i_peak=10, v_peak=100))
    publisher = Publisher("lo", rate=rate, asdus_per_frame=2, engine="python")
    publisher.add(stream)
    start = int(time.time()) + 1
    with cap:
        publisher.start(at_second=start)
        frames = []
        deadline = start + 1.3
        while time.time() < deadline:
            got = cap.recv()
            if got is not None:
                frames.append(got)
        publisher.stop()
    decoded = [(f.timestamp, sv.decode_sv_frame(f.data)[1]) for f in frames]  # type: ignore[index]
    first_second = [(ts, pdu) for ts, pdu in decoded if int(ts) == start]
    assert [a.smp_cnt for _ts, pdu in first_second for a in pdu.asdus] == list(range(rate))
    lateness = [ts - (start + pdu.asdus[0].smp_cnt / rate) for ts, pdu in first_second]
    assert 0 <= min(lateness) and max(lateness) < 0.02
    stats = publisher.stats()
    assert stats.engine == "python" and stats.frames_sent >= rate // 2 and stats.send_errors == 0


def test_command_line_matches_rt_sender_options(capsys: pytest.CaptureFixture[str]) -> None:
    from open61850.sv_publisher import _parser, main, stream_from_args

    args = _parser().parse_args(
        "processbus 02:00:00:00:0f:01 01:0c:cd:04:0f:01 IED01_TEST_SV1 --appid 0x4F01 --conf-rev 20000 --smp-synch 2 "
        "--vlan-id 105 --vlan-priority 5 --freq 50 --i-peak 354 --v-peak 51440 --phase 20 --fault --fault-i-peak 5000 "
        "--fault-v-peak 20000 --fault-phase 80 --fault-cycle 4 --fault-smpcnt 24 --fault-offset 1".split()
    )
    stream = stream_from_args(args)
    assert (stream.app_id, stream.conf_rev, stream.smp_synch, stream.vlan_id, stream.vlan_priority) == (0x4F01, 20000, 2, 105, 5)
    for sec, smp in [(1_790_000_000, 0), (1_790_000_001, 30), (1_790_000_002, 2400)]:
        fault = _rt_sender_in_fault(sec, smp, 4, 1, 24)
        theirs = _rt_sender_6i3u(smp, 50, 354, 51440, 20, fault, 5000, 20000, 80)
        ours = sample_values(stream, sec, smp, RATE)
        assert ours[:3] + ours[4:] == theirs[:3] + theirs[4:] and abs(ours[3] - theirs[3]) <= 1
    zero = stream_from_args(_parser().parse_args("lo 02:00:00:00:00:01 01:0c:cd:04:00:01 SV --appid 1 --conf-rev 1 --zero".split()))
    assert sample_values(zero, 1_790_000_000, 7, RATE) == [0] * 9
    assert main("lo 02:00:00:00:00:01 01:0c:cd:04:00:01 SV --appid 1 --conf-rev 1 --dump".split()) == 0
    raw = bytes.fromhex(capsys.readouterr().out.strip())
    assert sv.decode_sv_frame(raw)[1].asdus[0].sv_id == "SV"  # type: ignore[index]


# --- playback --------------------------------------------------------------------


def _pb_stream(**kwargs) -> SvStream:
    return SvStream("MU01", 0x4000, "01:0c:cd:04:00:01", "02:00:00:00:00:01",
                    (Wave(10, scale=1, quality=0x11), Wave(20, scale=1, quality=0x22)), **kwargs)


def test_playback_replaces_the_waves_for_its_duration() -> None:
    playback = Playback([(1, 2), (3, 4), (5, 6)], start_second=100, start_smp=10)
    stream = _pb_stream(playback=playback)
    rate = 4000
    assert sample_values(stream, 100, 9, rate) == sample_values(_pb_stream(), 100, 9, rate)
    assert [sample_values(stream, 100, n, rate) for n in (10, 11, 12)] == [[1, 2], [3, 4], [5, 6]]
    assert sample_values(stream, 100, 13, rate) == sample_values(_pb_stream(), 100, 13, rate)
    frame = render_frame(build_template(stream, 2, rate), stream, 100, 10, rate)
    asdus = sv.decode_sv_frame(frame)[1].asdus
    # without qualities, those of the normal waves
    assert [sv.decode_int32_samples(a.sample) for a in asdus] == [[(1, 0x11), (2, 0x22)], [(3, 0x11), (4, 0x22)]]


def test_playback_repeats_and_carries_qualities() -> None:
    playback = Playback([(7, 8)], start_second=0, repeat_s=2, qualities=[(0x1, 0x2)])
    stream = _pb_stream(playback=playback)
    template = build_template(stream, 1, 4000)
    for second in (0, 2, 4000):
        asdu = sv.decode_sv_frame(render_frame(template, stream, second, 0, 4000))[1].asdus[0]
        assert sv.decode_int32_samples(asdu.sample) == [(7, 1), (8, 2)]
    assert sample_values(stream, 1, 0, 4000) == sample_values(_pb_stream(), 1, 0, 4000)


def test_playback_checks() -> None:
    with pytest.raises(ValueError):
        Playback([])
    with pytest.raises(ValueError):
        Playback([(1, 2), (3,)])
    with pytest.raises(ValueError):
        Playback([(1, 2)], qualities=[(1, 2), (3, 4)])
    with pytest.raises(ValueError):
        build_template(_pb_stream(playback=Playback([(1, 2, 3)])), 1, 4000)
    unresolved = _pb_stream(playback=Playback([(1, 2)]))
    assert sample_values(unresolved, 0, 0, 4000) == sample_values(_pb_stream(), 0, 0, 4000)


def test_playback_starts_with_the_publisher() -> None:
    from open61850.sv_publisher import _resolve_playback

    resolved = _resolve_playback(_pb_stream(playback=Playback([(1, 2)], start_smp=5)), 1234)
    assert resolved.playback.start_second == 1234 and resolved.playback.start_smp == 5
    fixed = _pb_stream(playback=Playback([(1, 2)], start_second=9))
    assert _resolve_playback(fixed, 1234) is fixed


def test_playback_from_captured_frames() -> None:
    source = SvStream("MU09", 0x4001, "01:0c:cd:04:00:02", "02:00:00:00:00:09", three_phase(i_peak=10, v_peak=100))
    template = build_template(source, 2, 4800)
    frames = [render_frame(template, source, 7, first, 4800) for first in range(0, 12, 2)]
    frames.insert(2, frames[1])  # a duplicated frame is played once
    other = _pb_stream()
    frames.insert(0, render_frame(build_template(other, 1, 4800), other, 7, 0, 4800))
    playback = Playback.from_sv_frames(frames, "MU09", start_second=50)
    assert len(playback.values) == 12
    assert list(playback.values[3]) == sample_values(source, 7, 3, 4800)
    assert playback.qualities is not None and playback.channels == 9
    with pytest.raises(ValueError, match="no sample"):
        Playback.from_sv_frames(frames, "NOPE")


def test_command_line_replay_options(tmp_path) -> None:
    from test_comtrade import _write

    from open61850.pcap import PcapWriter
    from open61850.sv_publisher import _parser, playback_from_args

    base = ["lo", "02:00:00:00:00:01", "01:0c:cd:04:00:01", "MU01", "--appid", "0x4000", "--conf-rev", "1"]
    cfg = _write(tmp_path, "ASCII")
    args = _parser().parse_args(base + ["--comtrade", cfg, "--comtrade-channels", "IA,,,,,,1,,", "--replay-delay", "2",
                                        "--replay-repeat", "10"])
    waves = three_phase(i_peak=1, v_peak=1)
    playback = playback_from_args(args, waves, 1000)
    assert (playback.start_second, playback.repeat_s, playback.channels) == (1002, 10, 9)
    assert playback.values[0][1] == 0 and playback.values[0][6] != 0
    with pytest.raises(SystemExit, match="needs 9 entries"):
        playback_from_args(_parser().parse_args(base + ["--comtrade", cfg, "--comtrade-channels", "IA"]), waves, 0)

    source = SvStream("MU09", 0x4001, "01:0c:cd:04:00:02", "02:00:00:00:00:09", waves)
    template = build_template(source, 2, 4800)
    capture = tmp_path / "mu09.pcap"
    with PcapWriter(capture) as writer:
        for first in range(0, 20, 2):
            writer.write(render_frame(template, source, 3, first, 4800), 3 + first / 4800)
    args = _parser().parse_args(base + ["--replay-pcap", str(capture), "--replay-svid", "MU09"])
    playback = playback_from_args(args, waves, 1000)
    assert playback.start_second == 1000 and len(playback.values) == 20
    assert list(playback.values[5]) == sample_values(source, 3, 5, 4800)
    assert playback_from_args(_parser().parse_args(base), waves, 0) is None

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

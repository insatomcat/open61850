# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The native engine (open61850-rt): same bytes as render_frame, every sample on time on lo."""

from __future__ import annotations

import math
import random
import sys
import time

import pytest

from open61850 import sv
from open61850.sv_publisher import (
    TRUE_TIME,
    Clock,
    ClockState,
    Fault,
    Playback,
    Publisher,
    SvStream,
    Trajectory,
    Wave,
    _clock_next,
    _native_clock_state,
    _native_streams,
    build_template,
    render_frame,
    three_phase,
)

rt = pytest.importorskip("open61850_rt")
BASES = [0, 1_790_000_000, 2_000_000_000]


def _random_stream(rng: random.Random) -> SvStream:
    channels = rng.choice([8, 9, 3])
    waves = tuple(
        Wave(rng.uniform(0, 2000), rng.uniform(-360, 360), rng.choice([50.0, 60.0, 49.95, 0.0]),
             rng.uniform(-5, 5), rng.choice([1, 100, 1000]), rng.choice([0, 0x2000, 0x1]))
        for _ in range(channels)
    )
    fault = None
    if rng.random() < 0.6:
        fault = Fault(tuple(Wave(rng.uniform(0, 5e6), rng.uniform(-90, 90), 50.0, scale=1000) for _ in range(channels)),
                      cycle_s=rng.choice([1, 2, 4]), offset_s=rng.randint(-3, 5), start_smp=rng.randint(0, 5000),
                      duration_s=rng.choice([None, 0.25, 0.0, 10.0]))
    playback = None
    if rng.random() < 0.5:
        rows = rng.randint(1, 3000)
        values = [[rng.randint(-(1 << 31), (1 << 31) - 1) for _ in range(channels)] for _ in range(rows)]
        qualities = None if rng.random() < 0.5 else [[rng.randint(0, 0xFFFFFFFF) for _ in range(channels)]
                                                      for _ in range(rows)]
        kwargs = {"start_second": rng.choice(BASES) + rng.randint(0, 3), "start_smp": rng.randint(0, 4000),
                  "repeat_s": rng.choice([None, 1, 3])}
        if rng.random() < 0.5:
            playback = Playback(values, qualities=qualities, **kwargs)
        else:
            playback = Playback.from_array([v for r in values for v in r], channels, qualities=None if qualities is None
                                           else [q for r in qualities for q in r], **kwargs)
    return SvStream(sv_id=f"SV{rng.randint(0, 99)}", app_id=rng.randint(0, 0xFFFF), dst_mac="01:0c:cd:04:00:01",
                    src_mac="02:00:00:00:00:01", waves=waves, fault=fault, playback=playback,
                    vlan_id=rng.choice([None, 5]), vlan_priority=4, dat_set=rng.choice([None, "LD/LLN0$DS"]))


@pytest.mark.parametrize("seed", range(20))
def test_native_render_matches_python(seed: int) -> None:
    rng = random.Random(seed)
    rate, asdus = rng.choice([(4800, 2), (4000, 1), (14400, 6), (4800, 8)])
    streams = [_random_stream(rng) for _ in range(3)]
    templates = [build_template(s, asdus, rate) for s in streams]
    engine = rt.Engine("lo", rate, asdus, _native_streams(streams, templates, rate), 0)
    for _ in range(200):
        second = rng.choice(BASES) + rng.randint(0, 5)
        first = rng.randrange(0, rate, asdus)
        i = rng.randrange(len(streams))
        assert engine.render(i, second, first) == render_frame(templates[i], streams[i], second, first, rate)


@pytest.mark.parametrize("seed", range(10))
def test_native_shifted_render_matches_python(seed: int) -> None:
    rng = random.Random(500 + seed)
    rate, asdus = rng.choice([(4800, 2), (4000, 1), (14400, 6)])
    streams = [_random_stream(rng) for _ in range(3)]
    templates = [build_template(s, asdus, rate) for s in streams]
    engine = rt.Engine("lo", rate, asdus, _native_streams(streams, templates, rate), 0)
    for _ in range(200):
        second = rng.choice(BASES) + rng.randint(0, 5)
        first = rng.randrange(0, rate)
        shift = rng.choice([0, 1, -1, 1_000_000, -2_500_000, 37 * 10**9, rng.randint(-10**9, 10**9)])
        synch = rng.choice([None, 0, 1, 2, 5])
        i = rng.randrange(len(streams))
        assert engine.render(i, second, first, shift, synch) == render_frame(templates[i], streams[i], second, first,
                                                                             rate, shift, synch)


@pytest.mark.parametrize("seed", range(10))
def test_native_clock_matches_python(seed: int) -> None:
    rng = random.Random(700 + seed)
    rate = rng.choice([4800, 4000, 14400])
    base = rng.choice(BASES[1:]) * 1_000_000_000
    states, at = [], base
    for _ in range(rng.randint(1, 6)):
        at += rng.randint(1, 3 * 10**9)
        states.append(ClockState(at, offset_ns=rng.choice([0, 1000, -1_000_000, 37 * 10**9, rng.randint(-10**8, 10**8)]),
                                 drift_ppb=rng.choice([0.0, 50.0, -4000.0, rng.uniform(-1e5, 1e5)]),
                                 smp_synch=rng.choice([None, 1, 2])))
    clock = Clock(states)
    stream = SvStream("SV", 1, "01:0c:cd:04:00:01", "02:00:00:00:00:01", three_phase(i_peak=1, v_peak=1))
    engine = rt.Engine("lo", rate, 2, _native_streams([stream], [build_template(stream, 2, rate)], rate), 0)
    for st in states:
        engine.set_clock(*_native_clock_state(st))
    state, n = TRUE_TIME, base // 1_000_000_000 * rate
    for _ in range(3000):
        native = engine.clock_next(_native_clock_state(state), n)
        state, n, shift, target = _clock_next(clock, state, n, rate)
        assert native == (state.at_ns, n, shift, target)
        n += rng.choice([2, 2, 2, 999, 4800])
    with pytest.raises(ValueError):
        engine.set_clock(states[-1].at_ns, 0, 0.0, -1)  # not after the last state
    with pytest.raises(ValueError):
        engine.set_clock(states[-1].at_ns + 1, 0, 0.0, 256)


def _trajectory_points(rng: random.Random, channels: int, base: int) -> list[tuple[int, list[tuple[float, float]]]]:
    t, points = base * 1_000_000_000 + rng.randint(-10**9, 10**9), []
    for _ in range(rng.randint(1, 120)):
        points.append((t, [(rng.uniform(0, 3e5), rng.uniform(-50, 50)) for _ in range(channels)]))
        t += rng.choice([20_000_000, 10_000_000, 1, 33_333_333, rng.randint(1, 10**8)])
    return points


@pytest.mark.parametrize("seed", range(20))
def test_native_trajectory_matches_python(seed: int) -> None:
    rng = random.Random(1000 + seed)
    rate, asdus = rng.choice([(4800, 2), (4000, 1), (14400, 6)])
    base = rng.choice(BASES)
    streams, pushed = [], []
    for _ in range(3):
        channels = rng.choice([8, 3, 1])
        waves = tuple(Wave(rng.uniform(0, 100), 0, 50.0, 0, rng.choice([1, 100, 1000]), rng.choice([0, 0x2000]))
                      for _ in range(channels))
        points = _trajectory_points(rng, channels, base)
        early = rng.randint(0, len(points))  # some points before the engine is made, the others pushed
        t = Trajectory(channels, f0=rng.choice([50.0, 60.0]))
        for p in points[:early]:
            t.push(*p)
        streams.append(SvStream("SV", 1, "01:0c:cd:04:00:01", "02:00:00:00:00:01", waves, trajectory=t))
        pushed.append(points[early:])
    templates = [build_template(s, asdus, rate) for s in streams]
    engine = rt.Engine("lo", rate, asdus, _native_streams(streams, templates, rate), 0)
    for i, points in enumerate(pushed):
        for t_ns, p in points:
            engine.push(i, t_ns, p)
            streams[i].trajectory.push(t_ns, p)  # type: ignore[union-attr]
    # in increasing time, the way the engine sends: from before the first point to past the last
    k = (base - 2) * (rate // asdus)
    for _ in range(400):
        k += rng.choice([1, 1, 3, 40, 500])
        second, index = divmod(k, rate // asdus)
        for i in range(len(streams)):
            assert engine.render(i, second, index * asdus) == render_frame(templates[i], streams[i], second,
                                                                           index * asdus, rate)
    python_underruns = sum(s.trajectory.underruns for s in streams)  # type: ignore[union-attr]
    assert engine.stats()["trajectory_underruns"] == python_underruns


def test_native_trajectory_checks() -> None:
    stream = SvStream("SV", 1, "01:0c:cd:04:00:01", "02:00:00:00:00:01", (Wave(scale=1),), trajectory=Trajectory(1))
    engine = rt.Engine("lo", 4800, 2, _native_streams([stream], [build_template(stream, 2, 4800)], 4800), 0)
    engine.push(0, 5, [(1.0, 0.0)])
    with pytest.raises(ValueError):
        engine.push(0, 5, [(1.0, 0.0)])
    with pytest.raises(ValueError):
        engine.push(0, 6, [(1.0, 0.0), (1.0, 0.0)])
    with pytest.raises(ValueError):
        engine.push(1, 7, [(1.0, 0.0)])


def test_native_rejects_bad_input() -> None:
    stream = SvStream("SV", 1, "01:0c:cd:04:00:01", "02:00:00:00:00:01", three_phase(i_peak=1, v_peak=1))
    spec = _native_streams([stream], [build_template(stream, 2, 4800)], 4800)
    with pytest.raises(ValueError):
        rt.Engine("lo", 4800, 3, spec, 0)
    with pytest.raises(ValueError):
        rt.Engine("lo", 4800, 4, spec, 0)  # templates carry 2 ASDUs
    bad = dict(spec[0], sample_offsets=[10_000, 10_000])
    with pytest.raises(ValueError):
        rt.Engine("lo", 4800, 2, [bad], 0)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET is Linux only")
def test_native_engine_sends_every_sample_on_time() -> None:
    from open61850.capture import PacketCapture

    try:
        cap = PacketCapture("lo", (0x88BA,), timeout=0.05, outgoing=False, buffer_bytes=16 << 20)
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    rate = 4800
    streams = [SvStream(f"IED01_MU01_SV{n}", 0x4000 + n, "01:0c:cd:04:00:01", "02:00:00:00:00:01",
                        three_phase(i_peak=10, v_peak=100)) for n in range(3)]
    publisher = Publisher("lo", rate=rate, asdus_per_frame=2, engine="native")
    for s in streams:
        publisher.add(s)
    start = int(time.time()) + 1
    with cap:
        publisher.start(at_second=start)
        frames = []
        while time.time() < start + 1.2:
            got = cap.recv()
            if got is not None:
                frames.append(got)
        publisher.stop()
    per_stream: dict[str, list[int]] = {}
    lateness = []
    for f in frames:
        _eth, pdu = sv.decode_sv_frame(f.data)  # type: ignore[misc]
        if int(f.timestamp) != start:
            continue
        per_stream.setdefault(pdu.asdus[0].sv_id, []).extend(a.smp_cnt for a in pdu.asdus)
        lateness.append(f.timestamp - (start + pdu.asdus[0].smp_cnt / rate))
    assert sorted(per_stream) == [s.sv_id for s in streams]
    assert all(v == list(range(rate)) for v in per_stream.values())
    stats = publisher.stats()
    assert stats.engine == "native" and stats.send_errors == 0
    lateness.sort()
    print(f"\nlateness us: min {lateness[0]*1e6:.1f} median {lateness[len(lateness)//2]*1e6:.1f} "
          f"p99 {lateness[int(len(lateness)*0.99)]*1e6:.1f} max {lateness[-1]*1e6:.1f}")
    assert lateness[0] >= 0 and lateness[len(lateness) // 2] < 0.002


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET is Linux only")
def test_native_engine_plays_back_recorded_samples() -> None:
    from open61850.capture import PacketCapture

    try:
        cap = PacketCapture("lo", (0x88BA,), timeout=0.05, outgoing=False, buffer_bytes=16 << 20)
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    rate, rng = 4800, random.Random(9)
    values = [[rng.randint(-(1 << 31), (1 << 31) - 1) for _ in range(9)] for _ in range(rate)]
    stream = SvStream("IED01_MU01_PB", 0x4000, "01:0c:cd:04:00:01", "02:00:00:00:00:01",
                      three_phase(i_peak=10, v_peak=100), playback=Playback(values, start_smp=100))
    publisher = Publisher("lo", rate=rate, asdus_per_frame=2, engine="native")
    publisher.add(stream)
    start = int(time.time()) + 1
    received: dict[tuple[int, int], list[int]] = {}
    with cap:
        publisher.start(at_second=start)
        while time.time() < start + 1.3:
            got = cap.recv()
            if got is None:
                continue
            asdus = sv.decode_sv_frame(got.data)[1].asdus
            # A frame goes out at second + smpCnt / rate of its first sample, plus a small delay.
            second = round(got.timestamp - asdus[0].smp_cnt / rate)
            for asdu in asdus:
                received[(second, asdu.smp_cnt)] = [v for v, _q in sv.decode_int32_samples(asdu.sample)]
        publisher.stop()
    # sample n of the recording goes out as smpCnt 100 + n of the start second, then of the next one
    for n in range(0, rate, 97):
        second, smp = divmod(100 + n, rate)
        assert received[(start + second, smp)] == values[n]
    assert received[(start, 99)] != values[0]  # before the playback: the waves


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET is Linux only")
def test_native_engine_follows_a_trajectory_pushed_while_it_runs() -> None:
    from open61850.capture import PacketCapture

    try:
        cap = PacketCapture("lo", (0x88BA,), timeout=0.05, outgoing=False, buffer_bytes=16 << 20)
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    rate = 4800
    stream = SvStream("IED01_MU01_TR", 0x4000, "01:0c:cd:04:00:01", "02:00:00:00:00:01",
                      (Wave(scale=100),), trajectory=Trajectory(1))
    publisher = Publisher("lo", rate=rate, asdus_per_frame=2, engine="native")
    publisher.add(stream)
    start = int(time.time()) + 1
    received: dict[tuple[int, int], int] = {}
    # points 20 ms apart pushed 100 ms ahead of their time: a 0.5 Hz offset, 100 V peak; those of
    # the first 100 ms before the start, the engine preparing its first frame as it starts
    k = 0

    def due(t_ns: int) -> bool:
        return t_ns < max(time.time_ns(), start * 10**9) + 100_000_000

    while due(start * 10**9 + k * 20_000_000):
        publisher.push(0, start * 10**9 + k * 20_000_000, [(100.0, 2 * math.pi * 0.5 * k * 0.02)])
        k += 1
    with cap:
        publisher.start(at_second=start)
        while time.time() < start + 1.3:
            t_ns = start * 10**9 + k * 20_000_000
            if due(t_ns):
                publisher.push(0, t_ns, [(100.0, 2 * math.pi * 0.5 * k * 0.02)])
                k += 1
            got = cap.recv()
            if got is None:
                continue
            asdus = sv.decode_sv_frame(got.data)[1].asdus
            second = round(got.timestamp - asdus[0].smp_cnt / rate)
            for asdu in asdus:
                received[(second, asdu.smp_cnt)] = sv.decode_int32_samples(asdu.sample)[0][0]
        publisher.stop()
    for smp in range(0, rate, 13):
        x = smp / rate
        assert abs(received[(start, smp)] / 100 - 100 * math.cos(2 * math.pi * 50.5 * x)) < 0.02
    assert publisher.stats().trajectory_underruns == 0


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET is Linux only")
def test_native_engine_follows_its_clock() -> None:
    from open61850.capture import PacketCapture

    try:
        cap = PacketCapture("lo", (0x88BA,), timeout=0.05, outgoing=False, buffer_bytes=16 << 20)
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    rate = 4800
    stream = SvStream("IED01_MU01_CK", 0x4000, "01:0c:cd:04:00:01", "02:00:00:00:00:01",
                      three_phase(i_peak=10, v_peak=100), smp_synch=sv.SMP_SYNCH_GLOBAL)
    publisher = Publisher("lo", rate=rate, asdus_per_frame=2, engine="native")
    publisher.add(stream)
    start = int(time.time()) + 1
    ns = 1_000_000_000
    asdus = []
    with cap:
        publisher.start(at_second=start)
        # a grandmaster step of -1 ms at 0.5 s, then holdover: smpSynch local; at 0.8 s true time again
        publisher.set_clock(ClockState(start * ns + ns // 2, offset_ns=-1_000_000, smp_synch=sv.SMP_SYNCH_LOCAL))
        publisher.set_clock(ClockState(start * ns + 8 * ns // 10))
        while time.time() < start + 1.2:
            got = cap.recv()
            if got is not None and start <= got.timestamp < start + 1:
                asdus.extend(sv.decode_sv_frame(got.data)[1].asdus)
        publisher.stop()
    counts = [a.smp_cnt for a in asdus]
    # 2400 samples to 0.5 s, then back to the first taken at or after 0.5 s - 1 ms: 2396 (4.8 samples back)
    assert counts[:2400] == list(range(2400)) and counts[2400:2402] == [2396, 2397]
    # at 0.8 s, true time again: the frame of 3836, taken at 0.80017 s, is the first past it; it
    # starts at 3841, the first sample of true time at or after then (3836 to 3840 skipped: +1 ms)
    back = counts.index(3841, 2400)
    assert counts[back - 1] == 3835
    assert {a.smp_synch for a in asdus[:2400]} == {2} and {a.smp_synch for a in asdus[2400:back]} == {1}
    assert {a.smp_synch for a in asdus[back:]} == {2}  # the stream's own again

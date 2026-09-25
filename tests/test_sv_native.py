# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The native engine (open61850-rt): same bytes as render_frame, every sample on time on lo."""

from __future__ import annotations

import random
import sys
import time

import pytest

from open61850 import sv
from open61850.sv_publisher import Fault, Playback, Publisher, SvStream, Wave, build_template, render_frame, three_phase
from open61850.sv_publisher import _native_streams

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
        playback = Playback(values, start_second=rng.choice(BASES) + rng.randint(0, 3), start_smp=rng.randint(0, 4000),
                            repeat_s=rng.choice([None, 1, 3]), qualities=qualities)
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

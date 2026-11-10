# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850.sv_receiver: records of the streams asked for, both engines alike, the native one on lo."""

from __future__ import annotations

import socket
import struct
import sys
import time

import pytest

from open61850 import sv, sv_receiver
from open61850.sv_publisher import SvStream, Wave, build_template, render_frame
from open61850.sv_receiver import FLAG_CHANNELS, FLAG_SIMULATION, QUALITY_MISSING, Receiver, record_size

ENGINES = ["python"] + (["native"] if sv_receiver.native_available() else [])
RATE = 4800
T0 = 1_790_000_000


def _stream(sv_id: str, channels: int = 8, vlan: int | None = None) -> SvStream:
    waves = tuple(Wave(1000.0 * (k + 1), 30.0 * k, 50.0, scale=100, quality=0x2000 * (k % 2)) for k in range(channels))
    return SvStream(sv_id=sv_id, app_id=0x4000, dst_mac="01:0c:cd:04:00:01", src_mac="02:00:00:00:00:01",
                    waves=waves, vlan_id=vlan, vlan_priority=4)


def _frames(stream: SvStream, count: int, asdus: int = 2, simulation: bool = False) -> list[tuple[bytes, int]]:
    tpl = build_template(stream, asdus, RATE)
    out = []
    for j in range(count):
        first = j * asdus
        sec, smp = divmod(first, RATE)
        raw = bytearray(render_frame(tpl, stream, T0 + sec, smp, RATE))
        if simulation:
            raw[22 if stream.vlan_id is not None else 18] |= 0x80  # reserved1, after APPID and Length
        out.append((bytes(raw), (T0 + sec) * 1_000_000_000 + smp * 1_000_000_000 // RATE + 60_000))
    return out


def _records(data: bytes, channels: int) -> list[tuple]:
    size = record_size(channels)
    assert len(data) % size == 0
    fmt = struct.Struct(f"=qHBBI{channels}i{channels}I")
    return [fmt.unpack_from(data, k) for k in range(0, len(data), size)]


@pytest.mark.parametrize("engine", ENGINES)
def test_records_of_the_streams_asked_for(engine):
    a, b, c = _stream("MU01_SV"), _stream("MU02_SV", vlan=5), _stream("MU03_SV")
    rx = Receiver(["MU02_SV", "MU01_SV"], 8, engine=engine)
    frames = sorted(_frames(a, 10) + _frames(b, 10, simulation=True) + _frames(c, 10), key=lambda f: f[1])
    kept = sum(rx.feed(raw, ts) for raw, ts in frames)
    assert kept == 40
    assert rx.pending(0) == rx.pending(1) == 20
    st = rx.stats()
    assert (st.frames, st.records, st.other, st.not_sv, st.malformed, st.overflows) == (30, 40, 10, 0, 0, 0)
    for k, stream, sim in ((0, b, FLAG_SIMULATION), (1, a, 0)):
        recs = _records(rx.take(k), 8)
        assert [r[1] for r in recs] == list(range(20))
        tpl = build_template(stream, 2, RATE)
        for r in recs:
            ts, smp_cnt, synch, flags, conf_rev = r[:5]
            assert flags == sim and conf_rev == stream.conf_rev and synch == stream.smp_synch
            raw = render_frame(tpl, stream, T0, smp_cnt - smp_cnt % 2, RATE)
            asdu = sv.decode_sv_frame(raw)[1].asdus[smp_cnt % 2]
            pairs = sv.decode_int32_samples(asdu.sample)
            assert list(r[5:13]) == [v for v, _ in pairs] and list(r[13:21]) == [q for _, q in pairs]
            assert ts == T0 * 1_000_000_000 + (smp_cnt - smp_cnt % 2) * 1_000_000_000 // RATE + 60_000
        assert rx.pending(k) == 0 and rx.take(k) == b""


@pytest.mark.parametrize("engine", ENGINES)
def test_channels_short_or_long(engine):
    rx = Receiver(["S4", "S12"], 8, engine=engine)
    for raw, ts in _frames(_stream("S4", 4), 1) + _frames(_stream("S12", 12), 1):
        rx.feed(raw, ts)
    short, long_ = _records(rx.take(0), 8)[0], _records(rx.take(1), 8)[0]
    assert short[3] == long_[3] == FLAG_CHANNELS
    assert short[9:13] == (0, 0, 0, 0) and short[17:21] == (QUALITY_MISSING,) * 4
    pairs = sv.decode_int32_samples(sv.decode_sv_frame(_frames(_stream("S12", 12), 1)[0][0])[1].asdus[0].sample)
    assert list(long_[5:13]) == [v for v, _ in pairs[:8]]


@pytest.mark.parametrize("engine", ENGINES)
def test_malformed_not_sv_overflow(engine):
    rx = Receiver(["MU01_SV"], 8, capacity=5, engine=engine)
    good = _frames(_stream("MU01_SV"), 4)
    raw = bytearray(good[0][0])
    at = raw.index(b"\x80\x01\x02", 22)  # noASDU 2
    raw[at + 2] = 3  # two ASDUs present: the PDU no longer decodes
    rx.feed(bytes(raw), 0)
    rx.feed(b"\x01" * 12 + b"\x08\x00" + b"\x00" * 40, 0)
    for f in good:
        rx.feed(*f)
    st = rx.stats()
    assert st.malformed == 1 and st.not_sv == 1 and st.records == 5 and st.overflows == 3
    assert [r[1] for r in _records(rx.take(0), 8)] == [0, 1, 2, 3, 4]


def test_engines_give_the_same_bytes():
    if "native" not in ENGINES:
        pytest.skip("open61850-rt without the receiver")
    frames = _frames(_stream("A"), 50) + _frames(_stream("B", 5, vlan=7), 50, asdus=1, simulation=True)
    rxs = [Receiver(["B", "A"], 6, engine=e) for e in ENGINES]
    for raw, ts in frames:
        assert len({rx.feed(raw, ts) for rx in rxs}) == 1
    for k in (0, 1):
        assert len({rx.take(k) for rx in rxs}) == 1


@pytest.mark.parametrize("engine", ENGINES)
def test_wait(engine):
    rx = Receiver(["A", "B"], 8, engine=engine)
    t = time.monotonic()
    assert rx.wait([1, 1], timeout=0.05) is False
    assert time.monotonic() - t >= 0.04
    for f in _frames(_stream("B"), 3):
        rx.feed(*f)
    assert rx.wait([1, 7], timeout=0.05) is False
    assert rx.wait([1, 6], timeout=0.05) is True
    assert rx.wait([0, 100], timeout=0) is True
    with pytest.raises(ValueError):
        rx.wait([1])


def test_refusals():
    with pytest.raises(ValueError):
        Receiver([], 8)
    with pytest.raises(ValueError):
        Receiver(["A", "A"], 8)
    with pytest.raises(ValueError):
        Receiver(["A"], 8, engine="fast")
    rx = Receiver(["A"], 8, engine="python")
    with pytest.raises(IndexError):
        rx.take(1)
    with pytest.raises(ValueError):
        rx.start()


@pytest.mark.skipif(sys.platform != "linux", reason="AF_PACKET")
@pytest.mark.parametrize("engine", ENGINES)
def test_capture_on_lo(engine):
    from open61850.capture import PacketCapture

    try:
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    sender.bind(("lo", 0))
    frames = _frames(_stream("MU09_SV"), 50) + _frames(_stream("MU01_SV"), 200)  # the others first: wait() ends on the last
    with sender, PacketCapture("lo", (0x88BA,), timeout=0.05, outgoing=False, promiscuous=False,
                               low_latency=True) as cap:
        rx = Receiver(["MU01_SV"], 8, capture=cap, engine=engine)
        rx.start()
        try:
            t = time.monotonic()
            for raw, _ in frames:
                sender.send(raw)
            assert rx.wait([400], timeout=5.0)
            delay = time.monotonic() - t
        finally:
            rx.stop()
        st = rx.stats()
        recs = _records(rx.take(0), 8)
        assert [r[1] for r in recs] == list(range(400))
        assert st.records == 400 and st.other == 50 and st.malformed == 0
        now = time.time_ns()
        assert all(now - 10_000_000_000 < r[0] <= now for r in recs)
        assert delay < 5.0
        if engine == "native":
            # the slots the receiver read are given back; recv() resumes after them
            assert 0 <= cap.next_slot < cap.ring().slots
            sender2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sender2.bind(("lo", 0))
            with sender2:
                sender2.send(frames[0][0])
                f = cap.recv()
            assert f is not None and f.data == frames[0][0]

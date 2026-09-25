# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Sampled Values publication: streams, waveforms, frame templates and publishers.

A :class:`SvStream` describes one SV stream (addresses, APPID, svID, confRev,
smpSynch, VLAN) and the value of each channel over time (:class:`Wave`,
optionally a periodic :class:`Fault`, optionally recorded samples played
back with :class:`Playback`, from a capture or a COMTRADE record). A :class:`Publisher` sends one or more
streams at ``rate`` samples per second, ``asdus_per_frame`` samples per frame,
from an Ethernet interface (Linux, AF_PACKET, root or CAP_NET_RAW).

Timing follows the usual merging-unit convention: sample ``smpCnt`` of second
``s`` is taken at ``s + smpCnt / rate`` (UNIX time), smpCnt wraps every
second, and a frame goes out at the time of its first sample. Waveforms are
functions of that absolute time, so separate streams, processes or machines
synchronised on the same clock produce coherent phases.

Two engines send the frames:

- ``"native"``: the real-time engine of the ``open61850-rt`` package
  (``pip install "open61850[rt]"``): absolute-time sleeps on
  ``CLOCK_REALTIME``, optional real-time priority and CPU pinning, batched
  sends. This is the one for merging units and simulators.
- ``"python"``: the same frames from a Python thread. Its timing is only
  as good as ``time.sleep``; it serves tests, low rates and platforms without
  the native engine.

The frames themselves are built here in both cases: :func:`build_template`
encodes a frame once with :mod:`open61850.sv` and records where smpCnt and
the samples sit; :func:`render_frame` fills them in. The native engine
receives the templates and the waveform parameters and must produce the
same bytes as :func:`render_frame` (the tests check it).
"""

from __future__ import annotations

import argparse
import array
import collections
import dataclasses
import math
import signal
import socket
import sys
import struct
import threading
import time
from dataclasses import dataclass, field
from collections.abc import Iterable
from typing import Any, Optional, Sequence, Union

from . import ber, sv

__all__ = [
    "SIMULATION_BIT",
    "Wave",
    "Fault",
    "Playback",
    "SvStream",
    "Template",
    "PublisherStats",
    "Publisher",
    "three_phase",
    "build_template",
    "render_frame",
    "sample_values",
    "native_available",
    "main",
]

SIMULATION_BIT = 0x8000  # Reserved1 bit 15 (IEC 61850-9-2 Ed2.1): the stream is simulated
_I_SCALE = 1000  # 9-2LE: currents in mA
_V_SCALE = 100  # 9-2LE: voltages in 10 mV


@dataclass(frozen=True)
class Wave:
    """One channel: ``offset + amplitude * sin(2 pi freq_hz t + phase_deg)``, in engineering units.

    The value sent is that quantity times ``scale``, rounded to an INT32
    (9-2LE: 1000 for amperes, 100 for volts), followed by ``quality``.
    ``freq_hz`` 0 gives a constant ``offset``.
    """

    amplitude: float = 0.0
    phase_deg: float = 0.0
    freq_hz: float = 50.0
    offset: float = 0.0
    scale: float = 1.0
    quality: int = 0

    def value(self, second: int, smp_cnt: int, rate: int) -> int:
        """The INT32 sent for sample ``smp_cnt`` of UNIX second ``second``."""
        if self.freq_hz == 0.0 or self.amplitude == 0.0:
            x = self.offset
        else:
            # The phase is taken per second so that large UNIX times keep
            # their precision: frac(f * s) needs ~37 bits, leaving ~16 for the fraction.
            cycles = math.fmod(self.freq_hz * second, 1.0) + self.freq_hz * smp_cnt / rate
            x = self.offset + self.amplitude * math.sin(2.0 * math.pi * cycles + math.radians(self.phase_deg))
        return _int32(round(x * self.scale))


@dataclass(frozen=True)
class Fault:
    """A periodic fault, aligned on the UNIX epoch.

    Every ``cycle_s`` seconds, from second ``offset_s`` of the cycle and
    sample ``start_smp`` of that second, the stream sends ``waves`` instead of
    its normal ones for ``duration_s`` seconds (half the cycle by default).
    """

    waves: tuple[Wave, ...]
    cycle_s: int
    offset_s: int = 0
    start_smp: int = 0
    duration_s: Optional[float] = None

    def active(self, second: int, smp_cnt: int, rate: int) -> bool:
        cycle = max(1, self.cycle_s)
        period = cycle * rate
        start = (self.offset_s % cycle) * rate + min(max(self.start_smp, 0), rate - 1)
        length = period // 2 if self.duration_s is None else max(0, min(period, round(self.duration_s * rate)))
        return (second * rate + smp_cnt - start) % period < length


@dataclass(frozen=True)
class Playback:
    """Recorded samples sent instead of the waveforms (and of the fault).

    ``values[n][ch]`` is the INT32 of channel ``ch`` at the ``n``-th sample
    played, ``qualities`` the same for the quality (the normal waves' quality
    when ``None``). Sample 0 goes out as smpCnt ``start_smp`` of UNIX second
    ``start_second`` (``None``: the second the publisher starts); with
    ``repeat_s`` the recording starts again every ``repeat_s`` seconds.
    Outside the recording the stream sends its waves. The values must be at
    the publisher's rate: :meth:`from_sv_frames` and :meth:`from_comtrade`
    build them.
    """

    values: tuple[tuple[int, ...], ...]
    start_second: Optional[int] = None
    start_smp: int = 0
    repeat_s: Optional[int] = None
    qualities: Optional[tuple[tuple[int, ...], ...]] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", tuple(tuple(int(v) for v in row) for row in self.values))
        if self.qualities is not None:
            object.__setattr__(self, "qualities", tuple(tuple(int(q) for q in row) for row in self.qualities))
            if len(self.qualities) != len(self.values):
                raise ValueError("qualities must have one row per sample")
        if not self.values:
            raise ValueError("a playback needs samples")
        width = len(self.values[0])
        rows = self.values + (self.qualities or ())
        if any(len(row) != width for row in rows):
            raise ValueError("every sample must have the same number of channels")
        if self.repeat_s is not None and self.repeat_s < 1:
            raise ValueError("repeat_s must be at least 1")

    @property
    def channels(self) -> int:
        return len(self.values[0])

    def index(self, second: int, smp_cnt: int, rate: int) -> Optional[int]:
        """Row of ``values`` sent at this sample, or ``None`` outside the recording.

        A playback whose start the publisher has not set yet never plays.
        """
        if self.start_second is None:
            return None
        i = second * rate + smp_cnt - (self.start_second * rate + self.start_smp)
        if self.repeat_s is not None:
            i %= self.repeat_s * rate
        return i if 0 <= i < len(self.values) else None

    @classmethod
    def from_sv_frames(cls, frames: Iterable[bytes], sv_id: str, **kwargs: Any) -> Playback:
        """The samples of stream ``sv_id`` in captured SV frames (INT32 + quality data sets), in order.

        Frames of other streams, and samples whose smpCnt came among the last
        64 (a duplicated frame), are skipped.
        """
        values: list[tuple[int, ...]] = []
        qualities: list[tuple[int, ...]] = []
        recent: collections.deque[int] = collections.deque(maxlen=64)
        for raw in frames:
            decoded = sv.decode_sv_frame(raw)
            if decoded is None:
                continue
            for asdu in decoded[1].asdus:
                if asdu.sv_id != sv_id or asdu.smp_cnt in recent:
                    continue
                recent.append(asdu.smp_cnt)
                pairs = sv.decode_int32_samples(asdu.sample)
                values.append(tuple(v for v, _q in pairs))
                qualities.append(tuple(q for _v, q in pairs))
        if not values:
            raise ValueError(f"no sample of {sv_id!r} in the frames")
        return cls(tuple(values), qualities=tuple(qualities), **kwargs)

    @classmethod
    def from_comtrade(cls, record: Any, channels: Sequence[Union[int, str, None]], rate: int,
                      scales: Sequence[float], **kwargs: Any) -> Playback:
        """A COMTRADE record's analog channels, resampled to ``rate`` (primary values).

        ``channels`` names, for each channel of the stream, the record's
        analog channel (index or ch_id), or ``None`` for zero; ``scales``
        multiplies each before rounding (9-2LE: 1000 for A, 100 for V).
        """
        from .comtrade import resample

        if len(scales) != len(channels):
            raise ValueError("one scale per channel")
        times = record.times()
        columns = []
        for ref, scale in zip(channels, scales):
            if ref is None:
                columns.append(None)
                continue
            resampled = resample(times, record.analog(ref), rate)
            columns.append([_int32(round(x * scale)) for x in resampled])
        length = max((len(c) for c in columns if c is not None), default=0)
        if not length:
            raise ValueError("no channel taken from the record")
        rows = tuple(tuple(0 if c is None else c[n] for c in columns) for n in range(length))
        return cls(rows, **kwargs)


@dataclass
class SvStream:
    """One SV stream. ``waves`` gives the channels in data set order."""

    sv_id: str
    app_id: int
    dst_mac: str
    src_mac: str
    waves: Sequence[Wave]
    conf_rev: int = 1
    smp_synch: int = sv.SMP_SYNCH_NONE
    vlan_id: Optional[int] = None
    vlan_priority: Optional[int] = None
    dat_set: Optional[str] = None
    simulation: bool = False
    fault: Optional[Fault] = None
    playback: Optional[Playback] = None

    def waves_at(self, second: int, smp_cnt: int, rate: int) -> Sequence[Wave]:
        if self.fault is not None and self.fault.active(second, smp_cnt, rate):
            return self.fault.waves
        return self.waves


def three_phase(
    *,
    i_peak: float,
    v_peak: float,
    freq_hz: float = 50.0,
    i_lag_deg: float = 0.0,
    layout: str = "6I3U",
    ia_peak: Optional[float] = None,
    ia_lag_deg: Optional[float] = None,
    va_peak: Optional[float] = None,
    i_scale: float = _I_SCALE,
    v_scale: float = _V_SCALE,
) -> tuple[Wave, ...]:
    """Balanced three-phase channels, phase A optionally overridden (e.g. for a fault).

    ``layout`` "6I3U" (IEC 61869-9 F6I3U: Ia Ib Ic Ires In Ih Va Vb Vc) or
    "4I4U" (9-2LE: Ia Ib Ic In Va Vb Vc Vn). Currents lag the voltages by
    ``i_lag_deg``; Ires (and In in 4I4U) is the sum of the three currents.
    """

    def current(peak: float, lag: float, shift: float) -> Wave:
        return Wave(peak, -lag - shift, freq_hz, scale=i_scale)

    ia = current(i_peak if ia_peak is None else ia_peak, i_lag_deg if ia_lag_deg is None else ia_lag_deg, 0.0)
    ib = current(i_peak, i_lag_deg, 120.0)
    ic = current(i_peak, i_lag_deg, 240.0)
    residual = _phasor_sum((ia, ib, ic), freq_hz, i_scale)
    va = Wave(v_peak if va_peak is None else va_peak, 0.0, freq_hz, scale=v_scale)
    vb = Wave(v_peak, -120.0, freq_hz, scale=v_scale)
    vc = Wave(v_peak, -240.0, freq_hz, scale=v_scale)
    zero_i, zero_v = Wave(scale=i_scale), Wave(scale=v_scale)
    if layout.upper() == "6I3U":
        return (ia, ib, ic, residual, zero_i, zero_i, va, vb, vc)
    if layout.upper() == "4I4U":
        return (ia, ib, ic, residual, va, vb, vc, _phasor_sum((va, vb, vc), freq_hz, v_scale))
    raise ValueError(f"unknown layout {layout!r} (6I3U or 4I4U)")


def _phasor_sum(waves: Sequence[Wave], freq_hz: float, scale: float) -> Wave:
    re = sum(w.amplitude * math.cos(math.radians(w.phase_deg)) for w in waves)
    im = sum(w.amplitude * math.sin(math.radians(w.phase_deg)) for w in waves)
    amplitude = math.hypot(re, im)
    if amplitude < 1e-9:
        return Wave(freq_hz=freq_hz, scale=scale)
    return Wave(amplitude, math.degrees(math.atan2(im, re)), freq_hz, scale=scale)


def _int32(value: int) -> int:
    return max(-(1 << 31), min((1 << 31) - 1, value))


# --- frames ------------------------------------------------------------------


@dataclass(frozen=True)
class Template:
    """An encoded frame and where each ASDU keeps its smpCnt (2 bytes) and samples (8 bytes per channel)."""

    frame: bytes
    smp_cnt_offsets: tuple[int, ...]
    sample_offsets: tuple[int, ...]
    channels: int


def build_template(stream: SvStream, asdus_per_frame: int, rate: int) -> Template:
    """Encode one frame of ``stream`` with zero samples and locate its variable fields."""
    if not 1 <= asdus_per_frame <= 16:
        raise ValueError("asdus_per_frame must be 1 to 16")
    channels = len(stream.waves)
    if stream.fault is not None and len(stream.fault.waves) != channels:
        raise ValueError("the fault waves must have as many channels as the stream")
    if stream.playback is not None and stream.playback.channels != channels:
        raise ValueError("the playback must have as many channels as the stream")
    asdu = sv.SvAsdu(
        sv_id=stream.sv_id,
        smp_cnt=0,
        conf_rev=stream.conf_rev,
        smp_synch=stream.smp_synch,
        sample=bytes(8 * channels),
        dat_set=stream.dat_set,
    )
    frame = sv.encode_sv_frame(
        sv.SvPDU([asdu] * asdus_per_frame),
        dst_mac=stream.dst_mac,
        src_mac=stream.src_mac,
        app_id=stream.app_id,
        vlan_id=stream.vlan_id,
        vlan_priority=stream.vlan_priority,
    )
    if stream.simulation:
        frame = _set_reserved1(frame, SIMULATION_BIT)
    smp_offsets, sample_offsets = _locate(frame, asdus_per_frame)
    return Template(frame, tuple(smp_offsets), tuple(sample_offsets), channels)


def _set_reserved1(frame: bytes, bits: int) -> bytes:
    at = 18 if frame[12:14] == b"\x81\x00" else 14
    reserved1 = int.from_bytes(frame[at + 4 : at + 6], "big") | bits
    return frame[: at + 4] + reserved1.to_bytes(2, "big") + frame[at + 6 :]


def _locate(frame: bytes, asdus: int) -> tuple[list[int], list[int]]:
    """Offsets of smpCnt and sample in each ASDU of an encoded SV frame."""
    header = (18 if frame[12:14] == b"\x81\x00" else 14) + 8
    sav = ber.decode_tlv(frame, header)
    sav_start = sav.end - len(sav.value)
    seq = next(t for t in _tlvs_at(frame, sav_start, sav.end) if t.tag == 0xA2)
    smp_offsets, sample_offsets = [], []
    for item in _tlvs_at(frame, seq.end - len(seq.value), seq.end):
        for fld in _tlvs_at(frame, item.end - len(item.value), item.end):
            if fld.tag == 0x82:
                smp_offsets.append(fld.end - len(fld.value))
            elif fld.tag == 0x87:
                sample_offsets.append(fld.end - len(fld.value))
    if len(smp_offsets) != asdus or len(sample_offsets) != asdus:
        raise ValueError("unexpected SV frame layout")
    return smp_offsets, sample_offsets


def _tlvs_at(data: bytes, start: int, end: int) -> list[ber.Tlv]:
    out, offset = [], start
    while offset < end:
        tlv = ber.decode_tlv(data, offset)
        out.append(tlv)
        offset = tlv.end
    return out


def sample_values(stream: SvStream, second: int, smp_cnt: int, rate: int) -> list[int]:
    """The INT32 values of every channel of ``stream`` at one sample."""
    return [value for value, _quality in _samples(stream, second, smp_cnt, rate)]


def _samples(stream: SvStream, second: int, smp_cnt: int, rate: int) -> list[tuple[int, int]]:
    playback = stream.playback
    if playback is not None and (row := playback.index(second, smp_cnt, rate)) is not None:
        qualities = playback.qualities[row] if playback.qualities is not None else [w.quality for w in stream.waves]
        return list(zip(playback.values[row], qualities))
    return [(w.value(second, smp_cnt, rate), w.quality) for w in stream.waves_at(second, smp_cnt, rate)]


def render_frame(template: Template, stream: SvStream, second: int, first_smp: int, rate: int) -> bytes:
    """The frame carrying samples ``first_smp``, ``first_smp + 1``... of UNIX second ``second``."""
    frame = bytearray(template.frame)
    for i, (smp_at, sample_at) in enumerate(zip(template.smp_cnt_offsets, template.sample_offsets)):
        sec, smp = divmod(first_smp + i, rate)
        sec += second
        struct.pack_into("!H", frame, smp_at, smp)
        for ch, (value, quality) in enumerate(_samples(stream, sec, smp, rate)):
            struct.pack_into("!iI", frame, sample_at + 8 * ch, value, quality)
    return bytes(frame)


# --- publisher ---------------------------------------------------------------


def native_available() -> bool:
    """Whether the real-time engine (``open61850-rt``) is installed."""
    try:
        import open61850_rt  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class PublisherStats:
    frames_sent: int = 0
    send_errors: int = 0
    late_frames: int = 0  # sent more than one frame period after their time
    max_lateness_ns: int = 0
    engine: str = ""


@dataclass
class Publisher:
    """Sends SV streams from ``iface``.

    ``engine`` "auto" takes the native engine when installed, else Python.
    ``rt_priority`` (1-99, SCHED_FIFO) and ``cpu`` apply to the native engine.
    """

    iface: str
    rate: int = 4800
    asdus_per_frame: int = 2
    engine: str = "auto"
    rt_priority: Optional[int] = None
    cpu: Optional[int] = None
    streams: list[SvStream] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.rate % self.asdus_per_frame:
            raise ValueError("rate must be a multiple of asdus_per_frame")
        if self.engine not in ("auto", "native", "python"):
            raise ValueError("engine must be auto, native or python")
        self._runner: Any = None

    def add(self, stream: SvStream) -> None:
        if self._runner is not None:
            raise RuntimeError("add the streams before start()")
        self.streams.append(stream)

    @property
    def engine_name(self) -> str:
        if self.engine != "auto":
            return self.engine
        return "native" if native_available() else "python"

    def start(self, at_second: Optional[int] = None) -> None:
        """Start sending at the next whole second (or at UNIX second ``at_second``)."""
        if self._runner is not None:
            raise RuntimeError("already started")
        if not self.streams:
            raise ValueError("no stream to publish")
        start = at_second if at_second is not None else int(time.time()) + 1
        self.streams = [_resolve_playback(s, start) for s in self.streams]
        templates = [build_template(s, self.asdus_per_frame, self.rate) for s in self.streams]
        if self.engine_name == "native":
            import open61850_rt

            version = tuple(int(x) for x in open61850_rt.__version__.split(".")[:2])
            if version < (0, 4) and any(s.playback is not None for s in self.streams):
                raise RuntimeError(f"open61850-rt {open61850_rt.__version__} cannot play back samples: 0.4 or later")

            self._runner = open61850_rt.Engine(
                self.iface, self.rate, self.asdus_per_frame, _native_streams(self.streams, templates, self.rate),
                start, self.rt_priority, self.cpu,
            )
        else:
            self._runner = _PythonEngine(self.iface, self.rate, self.asdus_per_frame, self.streams, templates, start)
        self._runner.start()

    def stop(self) -> None:
        if self._runner is not None:
            self._runner.stop()

    def stats(self) -> PublisherStats:
        if self._runner is None:
            return PublisherStats(engine=self.engine_name)
        return PublisherStats(**self._runner.stats(), engine=self.engine_name)

    def __enter__(self) -> Publisher:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


def _resolve_playback(stream: SvStream, start: int) -> SvStream:
    """A playback without start second begins when the publisher does."""
    if stream.playback is None or stream.playback.start_second is not None:
        return stream
    return dataclasses.replace(stream, playback=dataclasses.replace(stream.playback, start_second=start))


def _native_streams(streams: Sequence[SvStream], templates: Sequence[Template], rate: int) -> list[dict[str, Any]]:
    """The plain data the native engine takes (see open61850_rt.Engine)."""

    def waves(ws: Sequence[Wave]) -> list[tuple[float, float, float, float, float, int]]:
        return [(w.amplitude, w.phase_deg, w.freq_hz, w.offset, w.scale, w.quality) for w in ws]

    out = []
    for stream, template in zip(streams, templates):
        fault = None
        if stream.fault is not None:
            f = stream.fault
            fault = {"waves": waves(f.waves), "cycle_s": f.cycle_s, "offset_s": f.offset_s,
                     "start_smp": f.start_smp, "duration_s": f.duration_s}
        playback = None
        if stream.playback is not None and stream.playback.start_second is not None:
            pb = stream.playback
            playback = {
                # Native-endian 32-bit integers, one row after the other.
                "values": array.array("i", [v for row in pb.values for v in row]).tobytes(),
                "qualities": None if pb.qualities is None else
                array.array("I", [q for row in pb.qualities for q in row]).tobytes(),
                "channels": pb.channels,
                "start": pb.start_second * rate + pb.start_smp,
                "period": None if pb.repeat_s is None else pb.repeat_s * rate,
            }
        out.append({
            "frame": template.frame,
            "smp_cnt_offsets": list(template.smp_cnt_offsets),
            "sample_offsets": list(template.sample_offsets),
            "waves": waves(stream.waves),
            "fault": fault,
            "playback": playback,
        })
    return out


class _PythonEngine:
    def __init__(
        self, iface: str, rate: int, asdus: int, streams: Sequence[SvStream], templates: Sequence[Template], start: int
    ) -> None:
        self.iface, self.rate, self.asdus = iface, rate, asdus
        self.streams, self.templates, self.start_second = list(streams), list(templates), start
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._stats = {"frames_sent": 0, "send_errors": 0, "late_frames": 0, "max_lateness_ns": 0}
        self._lock = threading.Lock()

    def start(self) -> None:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)  # type: ignore[attr-defined]
        sock.bind((self.iface, 0))
        self._thread = threading.Thread(target=self._run, args=(sock,), name="sv-publisher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def _run(self, sock: socket.socket) -> None:
        period_ns = 1_000_000_000 * self.asdus // self.rate
        frames_per_second = self.rate // self.asdus
        # Each deadline is computed from the second, so rounding never accumulates.
        k = 0
        with sock:
            while not self._stop.is_set():
                second, index = divmod(k, frames_per_second)
                second += self.start_second
                target = second * 1_000_000_000 + index * self.asdus * 1_000_000_000 // self.rate
                delay = target - time.time_ns()
                if delay > 0:
                    if self._stop.wait(delay / 1e9):
                        break
                lateness = time.time_ns() - target
                sent = errors = 0
                for stream, template in zip(self.streams, self.templates):
                    try:
                        sock.send(render_frame(template, stream, second, index * self.asdus, self.rate))
                        sent += 1
                    except OSError:
                        errors += 1
                with self._lock:
                    s = self._stats
                    s["frames_sent"] += sent
                    s["send_errors"] += errors
                    s["max_lateness_ns"] = max(s["max_lateness_ns"], lateness)
                    if lateness > period_ns:
                        s["late_frames"] += sent
                k += 1


# --- command line ------------------------------------------------------------


def _int_auto(text: str) -> int:
    return int(text, 0)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="open61850-sv",
        description="Publish one Sampled Values stream until stopped (SIGINT or SIGTERM). "
        "Options follow PO's rt_sender; waveforms are aligned on the UNIX epoch.",
    )
    p.add_argument("iface")
    p.add_argument("src_mac")
    p.add_argument("dst_mac")
    p.add_argument("svid")
    p.add_argument("--appid", type=_int_auto, required=True)
    p.add_argument("--conf-rev", type=_int_auto, required=True)
    p.add_argument("--smp-synch", type=int, default=0, choices=(0, 1, 2))
    p.add_argument("--vlan-id", type=int)
    p.add_argument("--vlan-priority", type=int, default=0)
    p.add_argument("--dat-set")
    p.add_argument("--simulation", action="store_true", help="set the Simulate bit (Reserved1)")
    p.add_argument("--rate", type=int, default=4800, help="samples per second (default 4800)")
    p.add_argument("--asdus", type=int, default=2, help="ASDUs per frame (default 2)")
    p.add_argument("--layout", default="6I3U", choices=("6I3U", "4I4U"))
    p.add_argument("--freq", type=float, default=50.0, help="Hz; 0 sends zeros")
    p.add_argument("--zero", action="store_true", help="send zeros")
    p.add_argument("--i-peak", type=float, default=10.0, help="peak current, A")
    p.add_argument("--v-peak", type=float, default=100.0, help="peak phase voltage, V")
    p.add_argument("--phase", type=float, default=0.0, help="current lag behind voltage, degrees")
    p.add_argument("--fault", action="store_true", help="periodic fault on phase A")
    p.add_argument("--fault-i-peak", type=float, default=0.0)
    p.add_argument("--fault-v-peak", type=float, default=0.0)
    p.add_argument("--fault-phase", type=float, default=0.0, help="phase A current lag during the fault")
    p.add_argument("--fault-cycle", type=int, default=2, help="seconds between fault starts")
    p.add_argument("--fault-smpcnt", type=int, default=0, help="smpCnt of the first fault sample")
    p.add_argument("--fault-offset", type=int, default=0, help="seconds into the cycle")
    p.add_argument("--replay-pcap", metavar="FILE", help="replay the samples of an SV stream captured in a pcap/pcapng")
    p.add_argument("--replay-svid", help="svID to take from --replay-pcap (default: SVID)")
    p.add_argument("--comtrade", metavar="CFG", help="replay a COMTRADE record, resampled to --rate")
    p.add_argument("--comtrade-channels", metavar="A,B,...",
                   help="record channel (ch_id or index from 0) for each stream channel, empty for zero")
    p.add_argument("--replay-delay", type=int, default=0, help="seconds after the start before the replay")
    p.add_argument("--replay-repeat", type=int, help="replay again every this many seconds")
    p.add_argument("--rt-priority", type=int, help="SCHED_FIFO priority of the sending thread (native engine)")
    p.add_argument("--cpu", type=int, help="pin the sending thread to this CPU (native engine)")
    p.add_argument("--engine", default="auto", choices=("auto", "native", "python"))
    p.add_argument("--duration", type=float, help="stop after this many seconds")
    p.add_argument("--dump", action="store_true", help="print the first frame in hex and exit")
    return p


def playback_from_args(args: argparse.Namespace, channels: Sequence[Wave], start: int) -> Optional[Playback]:
    """The --replay-pcap or --comtrade playback, starting ``--replay-delay`` seconds after ``start``."""
    timing = {"start_second": start + args.replay_delay, "repeat_s": args.replay_repeat}
    if args.replay_pcap and args.comtrade:
        raise SystemExit("open61850-sv: --replay-pcap and --comtrade exclude each other")
    if args.replay_pcap:
        from .pcap import read_pcap

        frames = (f.data for f in read_pcap(args.replay_pcap))
        return Playback.from_sv_frames(frames, args.replay_svid or args.svid, **timing)
    if args.comtrade:
        from .comtrade import load_comtrade

        refs: list[Union[int, str, None]] = []
        for text in (args.comtrade_channels or "").split(","):
            text = text.strip()
            refs.append(None if not text else int(text) if text.isdigit() else text)
        if len(refs) != len(channels):
            raise SystemExit(f"open61850-sv: --comtrade-channels needs {len(channels)} entries for {args.layout}")
        record = load_comtrade(args.comtrade)
        return Playback.from_comtrade(record, refs, args.rate, [w.scale for w in channels], **timing)
    return None


def stream_from_args(args: argparse.Namespace) -> SvStream:
    freq = 0.0 if args.zero else args.freq
    waves = three_phase(i_peak=args.i_peak, v_peak=args.v_peak, freq_hz=freq, i_lag_deg=args.phase, layout=args.layout)
    if freq == 0.0:
        waves = tuple(Wave(freq_hz=0.0, scale=w.scale) for w in waves)
    fault = None
    if args.fault:
        fault_waves = three_phase(i_peak=args.i_peak, v_peak=args.v_peak, freq_hz=freq, i_lag_deg=args.phase,
                                  layout=args.layout, ia_peak=args.fault_i_peak, ia_lag_deg=args.fault_phase,
                                  va_peak=args.fault_v_peak)
        if freq == 0.0:
            fault_waves = waves
        fault = Fault(fault_waves, cycle_s=args.fault_cycle, offset_s=args.fault_offset, start_smp=args.fault_smpcnt)
    return SvStream(
        sv_id=args.svid, app_id=args.appid, dst_mac=args.dst_mac, src_mac=args.src_mac, waves=waves,
        conf_rev=args.conf_rev, smp_synch=args.smp_synch, vlan_id=args.vlan_id,
        vlan_priority=args.vlan_priority if args.vlan_id is not None else None,
        dat_set=args.dat_set, simulation=args.simulation, fault=fault,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    stream = stream_from_args(args)
    start = int(time.time()) + 1
    playback = playback_from_args(args, stream.waves, start)
    if playback is not None:
        stream = dataclasses.replace(stream, playback=playback)
    if args.dump:
        template = build_template(stream, args.asdus, args.rate)
        print(render_frame(template, stream, int(time.time()), 0, args.rate).hex())
        return 0
    publisher = Publisher(args.iface, rate=args.rate, asdus_per_frame=args.asdus, engine=args.engine,
                          rt_priority=args.rt_priority, cpu=args.cpu)
    publisher.add(stream)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    start = max(start, int(time.time()) + 1)
    if playback is not None and playback.start_second != start + args.replay_delay:  # loading took a while
        stream = dataclasses.replace(stream, playback=dataclasses.replace(playback, start_second=start + args.replay_delay))
        publisher.streams[0] = stream
    publisher.start(at_second=start)
    vlan = f"VLAN {args.vlan_id} priority {args.vlan_priority}" if args.vlan_id is not None else "no VLAN"
    print(f"open61850-sv: {args.svid} APPID 0x{args.appid:04x} on {args.iface} ({vlan}), {args.rate} samples/s, "
          f"{args.asdus} ASDUs per frame, {args.layout}, engine {publisher.engine_name}, from {start}", file=sys.stderr)
    if playback is not None:
        again = f", every {args.replay_repeat} s" if args.replay_repeat else ""
        print(f"open61850-sv: replaying {len(playback.values)} samples from {start + args.replay_delay}{again}",
              file=sys.stderr)
    stop.wait(None if args.duration is None else max(0.0, start + args.duration - time.time()))
    publisher.stop()
    print(f"open61850-sv: {publisher.stats()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

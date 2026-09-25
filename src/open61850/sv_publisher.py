# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Sampled Values publication: streams, waveforms, frame templates and publishers.

A :class:`SvStream` describes one SV stream (addresses, APPID, svID, confRev,
smpSynch, VLAN) and the value of each channel over time (:class:`Wave`,
optionally a periodic :class:`Fault`). A :class:`Publisher` sends one or more
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

import math
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from . import ber, sv

__all__ = [
    "SIMULATION_BIT",
    "Wave",
    "Fault",
    "SvStream",
    "Template",
    "PublisherStats",
    "Publisher",
    "three_phase",
    "build_template",
    "render_frame",
    "sample_values",
    "native_available",
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
    return [w.value(second, smp_cnt, rate) for w in stream.waves_at(second, smp_cnt, rate)]


def render_frame(template: Template, stream: SvStream, second: int, first_smp: int, rate: int) -> bytes:
    """The frame carrying samples ``first_smp``, ``first_smp + 1``... of UNIX second ``second``."""
    frame = bytearray(template.frame)
    for i, (smp_at, sample_at) in enumerate(zip(template.smp_cnt_offsets, template.sample_offsets)):
        sec, smp = divmod(first_smp + i, rate)
        sec += second
        struct.pack_into("!H", frame, smp_at, smp)
        waves = stream.waves_at(sec, smp, rate)
        for ch, wave in enumerate(waves):
            struct.pack_into("!iI", frame, sample_at + 8 * ch, wave.value(sec, smp, rate), wave.quality)
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
        templates = [build_template(s, self.asdus_per_frame, self.rate) for s in self.streams]
        if self.engine_name == "native":
            import open61850_rt

            self._runner = open61850_rt.Engine(
                self.iface, self.rate, self.asdus_per_frame, _native_streams(self.streams, templates),
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


def _native_streams(streams: Sequence[SvStream], templates: Sequence[Template]) -> list[dict[str, Any]]:
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
        out.append({
            "frame": template.frame,
            "smp_cnt_offsets": list(template.smp_cnt_offsets),
            "sample_offsets": list(template.sample_offsets),
            "waves": waves(stream.waves),
            "fault": fault,
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

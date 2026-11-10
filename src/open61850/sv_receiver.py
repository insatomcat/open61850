# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Sampled Values received for a few streams, kept as records of samples.

A subscriber of a few streams on a process bus sees every stream's frames,
thousands a second, and keeps a handful. :class:`Receiver` reads them in a
thread of its own and hands over, for each stream it was given, the
samples received since the last call, as fixed-size records in one
``bytes`` object: the caller wakes once for many samples, when it has
work to do (a phasor estimator, once per report), instead of once per
frame.

Two engines, as for the publisher:

- ``"native"``: the real-time engine of ``open61850-rt`` (Linux). Its
  thread reads the low-latency ring of a :class:`~open61850.capture.PacketCapture`
  (TPACKET_V2) itself and decodes with ``open61850-core``; it takes no
  Python object per frame and does not hold the GIL. ``cpu`` pins it,
  ``rt_priority`` gives it SCHED_FIFO.
- ``"python"``: a thread on :meth:`PacketCapture.recv` and
  :func:`open61850.sv.decode_sv_frame`. Frames that hold none of the
  svIDs' octets are counted and left undecoded.

``"auto"`` takes the native engine when it is installed. Both engines'
:meth:`Receiver.feed` take a frame by hand (tests, files) and give the
same records.

**A record** (native byte order, :func:`record_size` octets)::

    int64   ts_ns       the frame's capture time, UNIX nanoseconds
    uint16  smp_cnt
    uint8   smp_synch
    uint8   flags       FLAG_SIMULATION: the frame's Simulation bit (reserved1 bit 15)
                        FLAG_CHANNELS: the ASDU did not carry `channels` INT32 values
    uint32  conf_rev
    int32   value[channels]
    uint32  quality[channels]

An ASDU carrying more channels than asked gives the first ones; one
carrying fewer gives value 0 and quality 1 (validity invalid) for the
others, and both set FLAG_CHANNELS. NumPy reads a block with
``numpy.frombuffer(data, dtype)``, ``dtype`` being::

    numpy.dtype([("ts_ns", "=i8"), ("smp_cnt", "=u2"), ("smp_synch", "u1"), ("flags", "u1"),
                 ("conf_rev", "=u4"), ("value", "=i4", (channels,)), ("quality", "=u4", (channels,))])

**The buffer** of a stream holds ``capacity`` records; past that a new
record is dropped and counted (``overflows``), and the caller sees the
gap in smpCnt. :meth:`Receiver.wait` blocks, without the GIL for the
native engine, until a stream holds as many records as asked or a
timeout expires.

The capture belongs to the caller: open it with ``low_latency=True`` for
the native engine, stop the receiver before closing it. On stop the
native engine leaves :attr:`PacketCapture.next_slot` where it stopped.

Example::

    with PacketCapture("eth1", (ETHERTYPE_SV,), low_latency=True) as cap:
        rx = Receiver(["MU01_SV", "MU02_SV"], channels=8, capture=cap)
        rx.start()
        while True:
            rx.wait([96, 96], timeout=0.05)
            for k in range(2):
                block = numpy.frombuffer(rx.take(k), dtype)
"""

from __future__ import annotations

import ctypes
import struct
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Optional

from . import sv

__all__ = [
    "FLAG_SIMULATION",
    "FLAG_CHANNELS",
    "QUALITY_MISSING",
    "Receiver",
    "ReceiverStats",
    "record_size",
]

FLAG_SIMULATION = 1
FLAG_CHANNELS = 2
QUALITY_MISSING = 1  # validity "invalid", for a channel the ASDU did not carry
_HEADER = struct.Struct("=qHBBI")


def record_size(channels: int) -> int:
    """Octets of one record of ``channels`` channels."""
    return _HEADER.size + 8 * channels


@dataclass
class ReceiverStats:
    frames: int = 0  # frames seen
    records: int = 0  # ASDUs of the streams asked for, kept
    other: int = 0  # SV frames holding none of the streams asked for (the Python engine leaves them undecoded)
    not_sv: int = 0  # frames that are not SV
    malformed: int = 0  # SV frames that do not decode
    overflows: int = 0  # records dropped, a stream's buffer full
    engine: str = ""


def native_available() -> bool:
    """Whether open61850-rt has the receiver (0.9.21 or later)."""
    try:
        import open61850_rt
    except ImportError:
        return False
    return hasattr(open61850_rt, "Receiver")


class _PythonEngine:
    def __init__(self, sv_ids: list[bytes], channels: int, capacity: int) -> None:
        self.ids = {s.decode("ascii"): k for k, s in enumerate(sv_ids)}
        self.raw_ids = tuple(sv_ids)
        self.channels = channels
        self.capacity = capacity
        self.bufs: list[list[bytes]] = [[] for _ in sv_ids]
        self.stats = ReceiverStats(engine="python")
        self.cond = threading.Condition()
        self.stop_flag = False
        self.thread: Optional[threading.Thread] = None
        self.value_fmt = struct.Struct(f"={channels}i{channels}I")

    def record(self, ts_ns: int, asdu: sv.SvAsdu, simulation: bool) -> bytes:
        pairs = sv.decode_int32_samples(asdu.sample)
        flags = FLAG_SIMULATION if simulation else 0
        n = self.channels
        if len(pairs) != n:
            flags |= FLAG_CHANNELS
            pairs = (pairs + [(0, QUALITY_MISSING)] * n)[:n]
        return _HEADER.pack(ts_ns, asdu.smp_cnt, asdu.smp_synch, flags, asdu.conf_rev) + self.value_fmt.pack(
            *(v for v, _ in pairs), *(q for _, q in pairs))

    def feed(self, raw: bytes, ts_ns: int) -> int:
        st = self.stats
        st.frames += 1
        if not any(s in raw for s in self.raw_ids):
            if raw[12:14] == b"\x88\xba" or raw[16:18] == b"\x88\xba":
                st.other += 1
            else:
                st.not_sv += 1
            return 0
        try:
            decoded = sv.decode_sv_frame(raw)
            if decoded is None:
                st.not_sv += 1
                return 0
            eth, pdu = decoded
            simulation = bool(eth.reserved1 & 0x8000)
            out = []
            for asdu in pdu.asdus:
                k = self.ids.get(asdu.sv_id)
                if k is not None:
                    out.append((k, self.record(ts_ns, asdu, simulation)))
        except (ValueError, IndexError):  # SvDecodeError is a ValueError
            st.malformed += 1
            return 0
        if not out:
            st.other += 1
            return 0
        kept = 0
        with self.cond:
            for k, rec in out:
                if len(self.bufs[k]) >= self.capacity:
                    st.overflows += 1
                else:
                    self.bufs[k].append(rec)
                    kept += 1
            st.records += kept
            self.cond.notify_all()
        return kept

    def pending(self, k: int) -> int:
        with self.cond:
            return len(self.bufs[k])

    def take(self, k: int) -> bytes:
        with self.cond:
            data = b"".join(self.bufs[k])
            self.bufs[k] = []
        return data

    def wait(self, need: list[int], timeout: Optional[float]) -> bool:
        def ready() -> bool:
            return any(len(b) >= n for b, n in zip(self.bufs, need))

        with self.cond:
            return self.cond.wait_for(ready, timeout)

    def start(self, capture: Any) -> None:
        self.stop_flag = False

        def run() -> None:
            while not self.stop_flag:
                f = capture.recv()
                if f is not None:
                    self.feed(f.data, round(f.timestamp * 1e9))

        self.thread = threading.Thread(target=run, name="sv-receiver", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_flag = True
        if self.thread is not None:
            self.thread.join()
            self.thread = None


class Receiver:
    """The records of the SV streams ``sv_ids``, ``channels`` INT32 channels each (see the module's notes).

    ``capacity``: records each stream's buffer holds (4800 samples/s for
    four seconds by default). ``engine`` "auto", "native" or "python";
    ``cpu`` and ``rt_priority`` (SCHED_FIFO, 1-99) apply to the native
    engine's thread.
    """

    def __init__(self, sv_ids: Sequence[str | bytes], channels: int = 8, *, capture: Any = None,
                 capacity: int = 19200, engine: str = "auto", cpu: Optional[int] = None,
                 rt_priority: Optional[int] = None) -> None:
        if engine not in ("auto", "native", "python"):
            raise ValueError("engine must be auto, native or python")
        if not sv_ids:
            raise ValueError("no stream to receive")
        if channels <= 0 or capacity <= 0:
            raise ValueError("channels and capacity must be positive")
        ids = [s.encode("ascii") if isinstance(s, str) else bytes(s) for s in sv_ids]
        if len(set(ids)) != len(ids):
            raise ValueError("an svID is given twice")
        self.sv_ids = tuple(ids)
        self.channels = channels
        self.capture = capture
        self.engine_name = ("native" if native_available() else "python") if engine == "auto" else engine
        self._started = False
        self._ring_view: Any = None
        if self.engine_name == "native":
            if not native_available():
                raise RuntimeError("the native engine needs open61850-rt 0.9.21 or later")
            import open61850_rt

            self._native = open61850_rt.Receiver(list(ids), channels, capacity, cpu, rt_priority)
            self._python: Optional[_PythonEngine] = None
        else:
            self._native = None
            self._python = _PythonEngine(ids, channels, capacity)

    @property
    def record_size(self) -> int:
        return record_size(self.channels)

    def feed(self, raw: bytes, ts_ns: int) -> int:
        """One frame captured at ``ts_ns`` (UNIX ns) by hand; returns the records kept."""
        if self._native is not None:
            return int(self._native.feed(raw, ts_ns))
        assert self._python is not None
        return self._python.feed(raw, ts_ns)

    def start(self) -> None:
        """Read the capture from a thread of its own until :meth:`stop`."""
        if self._started:
            raise RuntimeError("already started")
        cap = self.capture
        if cap is None:
            raise ValueError("no capture to read")
        if self._native is not None:
            if not cap.low_latency:
                raise ValueError("the native engine reads a low-latency capture (TPACKET_V2)")
            ring = cap.ring()
            # a view of the mapping: its address for the thread, and the mmap refuses to close while it lives
            self._ring_view = (ctypes.c_char * (ring.slot_size * ring.slots)).from_buffer(ring.buffer)
            self._native.start(cap.fileno(), ctypes.addressof(self._ring_view), ring.slot_size, ring.slots,
                               cap.next_slot, cap.outgoing)
        else:
            assert self._python is not None
            self._python.start(cap)
        self._started = True

    def stop(self) -> None:
        if not self._started:
            return
        if self._native is not None:
            self.capture.next_slot = self._native.stop()
            self._ring_view = None
        else:
            assert self._python is not None
            self._python.stop()
        self._started = False

    def pending(self, stream: int) -> int:
        """Records stream ``stream`` (its index in ``sv_ids``) holds."""
        self._index(stream)
        if self._native is not None:
            return int(self._native.pending(stream))
        assert self._python is not None
        return self._python.pending(stream)

    def take(self, stream: int) -> bytes:
        """The records of stream ``stream`` since the last call, oldest first; its buffer emptied."""
        self._index(stream)
        if self._native is not None:
            return bytes(self._native.take(stream))
        assert self._python is not None
        return self._python.take(stream)

    def wait(self, need: Optional[Sequence[int]] = None, timeout: Optional[float] = None) -> bool:
        """Block until some stream ``k`` holds ``need[k]`` records (1 each by default); False on timeout.

        ``timeout`` None waits without end; a need of 0 is met at once.
        """
        counts = [1] * len(self.sv_ids) if need is None else [max(0, int(n)) for n in need]
        if len(counts) != len(self.sv_ids):
            raise ValueError("one need per stream")
        t = -1.0 if timeout is None else max(0.0, float(timeout))
        if self._native is not None:
            return bool(self._native.wait(counts, t))
        assert self._python is not None
        return self._python.wait(counts, None if t < 0 else t)

    def stats(self) -> ReceiverStats:
        if self._native is not None:
            return ReceiverStats(**self._native.stats(), engine="native")
        assert self._python is not None
        st = self._python.stats
        with self._python.cond:
            return ReceiverStats(st.frames, st.records, st.other, st.not_sv, st.malformed, st.overflows, "python")

    def _index(self, stream: int) -> None:
        if not 0 <= stream < len(self.sv_ids):
            raise IndexError(f"no stream {stream}")

    def __enter__(self) -> Receiver:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

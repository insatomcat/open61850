# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Supervision of GOOSE and Sampled Values streams, as a subscriber sees them.

What the LGOS and LSVS logical nodes of IEC 61850-7-4 watch, for a test or
diagnostic tool: each stream's counters, the time it may stay silent, and
its configuration. The supervisors only keep state: feed them decoded
messages with their reception time, from :class:`~open61850.capture.PacketCapture`
or from a file (:func:`open61850.pcap.read_pcap`), and they return
:class:`Event` objects. :meth:`GooseSupervisor.check` and
:meth:`SvSupervisor.check` report the streams that went silent.

GOOSE (key: gocbRef), IEC 61850-8-1 retransmission scheme:

- stNum + 1 with a new sqNum is a ``STATE_CHANGE`` (``missed``: stNum values
  skipped); allData that changes without a new stNum is
  ``DATA_WITHOUT_STATE_CHANGE``;
- within one stNum, a skipped sqNum is a ``GAP``, one received already a
  ``DUPLICATE``, an older one never seen ``OUT_OF_ORDER`` (it then comes
  off the missed count);
- a stNum that goes back is a ``RESTART`` (the publisher restarted): it
  becomes the new reference, so the stream is followed again at once;
- no message within timeAllowedtoLive is a ``TIMEOUT``, the next message
  ``RESUMED``; confRev, datSet, goID or numDatSetEntries changing is
  ``CONFIG_CHANGED``; the simulation and ndsCom flags are reported when set
  and when they change.

Sampled Values (key: svID), per ASDU: smpCnt must count up by one and wrap
to 0 once per second. The wrap value is the ``sample_rate`` given to the
supervisor, the ASDU's smpRate when smpMod says samples per second, or else
learnt from the highest smpCnt seen before the first wrap (a loss on that
very first wrap is then not seen). A counter up to 16 samples behind is a
``DUPLICATE`` or ``OUT_OF_ORDER`` as for GOOSE; further behind, or half a
second or more ahead, it is a ``RESTART`` (modulo the wrap, a loss count
would mean nothing). smpSynch changing is ``SYNCH_CHANGED``.

:class:`BusSupervisor` takes raw frames of both kinds and counts the ones
that do not decode. ``open61850-supervise`` (``python -m
open61850.supervision``) runs it on a capture file or a live interface.
"""

from __future__ import annotations

import enum
import itertools
from collections import Counter, deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Optional, Union

from . import ber, ethernet, goose, sv
from .capture import CapturedFrame
from .data import encode_data

__all__ = [
    "EventKind",
    "Event",
    "GooseStream",
    "GooseSupervisor",
    "SvStreamState",
    "SvSupervisor",
    "BusSupervisor",
]


_UINT32_MAX = 0xFFFFFFFF
REORDER_WINDOW = 16  # a counter this far back is a late or repeated message, further back a restart


class EventKind(enum.Enum):
    NEW_STREAM = "new stream"
    STATE_CHANGE = "state change"
    DATA_WITHOUT_STATE_CHANGE = "data changed without a new stNum"
    GAP = "gap"
    DUPLICATE = "duplicate"
    OUT_OF_ORDER = "out of order"
    RESTART = "restart"
    TIMEOUT = "timeout"
    RESUMED = "resumed"
    CONFIG_CHANGED = "configuration changed"
    SIMULATION = "simulation"
    NDS_COM = "ndsCom"
    SYNCH_CHANGED = "smpSynch changed"
    INCONSISTENT = "inconsistent message"


@dataclass(frozen=True)
class Event:
    """Something a supervisor noticed on one stream (gocbRef or svID).

    ``missed`` counts the messages (GOOSE), samples (SV) or states (GOOSE
    ``STATE_CHANGE``) that never arrived.
    """

    kind: EventKind
    stream: str
    timestamp: float
    detail: str = ""
    missed: int = 0

    def __str__(self) -> str:
        detail = f": {self.detail}" if self.detail else ""
        return f"{self.timestamp:.6f} {self.stream} {self.kind.value}{detail}"


_Emit = Callable[..., None]


def _counts() -> Counter[EventKind]:
    return Counter()


def _recent() -> deque[int]:
    return deque(maxlen=REORDER_WINDOW)


def _late(stream: Union[GooseStream, SvStreamState], value: int, what: str, after: int, emit: _Emit) -> bool:
    """A counter behind the reference: seen already (a duplicate) or arriving late.

    A late message was counted in a gap: it comes off the missed count.
    """
    if value in stream.recent:
        emit(EventKind.DUPLICATE, what)
    else:
        emit(EventKind.OUT_OF_ORDER, f"{what} after {after}")
        stream.recent.append(value)
        stream.missed = max(0, stream.missed - 1)
    return False


def _count(stream: Union[GooseStream, SvStreamState], events: Iterable[Event]) -> None:
    for event in events:
        stream.events[event.kind] += 1


# --- GOOSE -------------------------------------------------------------------


@dataclass
class GooseStream:
    """What a :class:`GooseSupervisor` knows of one gocbRef."""

    gocb_ref: str
    first_seen: float
    last_seen: float
    last: goose.GoosePDU
    app_id: Optional[int] = None
    src_mac: Optional[str] = None
    messages: int = 0
    missed: int = 0
    timed_out: bool = False
    events: Counter[EventKind] = field(default_factory=_counts)
    recent: deque[int] = field(default_factory=_recent, repr=False)  # counters last accepted

    @property
    def deadline(self) -> float:
        """Time after which the stream is silent for longer than its timeAllowedtoLive."""
        return self.last_seen + self.last.time_allowed_to_live / 1000


def _st_ahead(previous: int, current: int) -> int:
    """How far stNum moved forward (0 if it did not), with the wrap from 2^32 - 1 to 1."""
    if current > previous:
        return current - previous
    if previous == _UINT32_MAX and current >= 1:
        return current
    return 0


def _sq_next(previous: int, current: int) -> bool:
    return current == previous + 1 or (previous == _UINT32_MAX and current in (0, 1))


def _changed_entries(old: list, new: list) -> list[int]:
    if len(old) != len(new):
        return list(range(max(len(old), len(new))))
    # Encoded bytes decide: NaN != NaN in Python, but a repeated NaN has the same bytes.
    return [i for i, (a, b) in enumerate(zip(old, new)) if a != b and encode_data(a) != encode_data(b)]


def _consistent(pdu: goose.GoosePDU) -> bool:
    return pdu.num_dat_set_entries == len(pdu.all_data)


def _compare_goose_config(prev: goose.GoosePDU, pdu: goose.GoosePDU, emit: _Emit) -> None:
    changes = [
        f"{name} {a} -> {b}"
        for name, a, b in (
            ("confRev", prev.conf_rev, pdu.conf_rev),
            ("datSet", prev.dat_set, pdu.dat_set),
            ("goID", prev.go_id, pdu.go_id),
            ("numDatSetEntries", prev.num_dat_set_entries, pdu.num_dat_set_entries),
        )
        if a != b
    ]
    if changes:
        emit(EventKind.CONFIG_CHANGED, ", ".join(changes))
    if pdu.simulation != prev.simulation:
        emit(EventKind.SIMULATION, "simulation bit " + ("set" if pdu.simulation else "cleared"))
    if pdu.nds_com != prev.nds_com:
        emit(EventKind.NDS_COM, "ndsCom " + ("set" if pdu.nds_com else "cleared"))


def _follow_goose(stream: GooseStream, pdu: goose.GoosePDU, emit: _Emit) -> bool:
    """Classify stNum and sqNum against the last accepted message; True if ``pdu`` replaces it."""
    prev = stream.last
    if pdu.st_num == prev.st_num:
        if pdu.sq_num == prev.sq_num or (pdu.sq_num < prev.sq_num and not _sq_next(prev.sq_num, pdu.sq_num)):
            return _late(stream, pdu.sq_num, f"stNum {pdu.st_num} sqNum {pdu.sq_num}", prev.sq_num, emit)
        if not _sq_next(prev.sq_num, pdu.sq_num):
            missed = pdu.sq_num - prev.sq_num - 1
            emit(EventKind.GAP, f"sqNum {prev.sq_num} -> {pdu.sq_num}", missed)
            stream.missed += missed
        if changed := _changed_entries(prev.all_data, pdu.all_data):
            emit(EventKind.DATA_WITHOUT_STATE_CHANGE, f"stNum {pdu.st_num}, entries {changed}")
        return True
    stream.recent.clear()  # sqNum starts again
    ahead = _st_ahead(prev.st_num, pdu.st_num)
    if not ahead:
        emit(EventKind.RESTART, f"stNum {prev.st_num} -> {pdu.st_num}")
        return True
    detail = f"stNum {prev.st_num} -> {pdu.st_num}, entries {_changed_entries(prev.all_data, pdu.all_data)}"
    if pdu.sq_num > 1:
        detail += f", first sqNum {pdu.sq_num}"
    emit(EventKind.STATE_CHANGE, detail, ahead - 1)
    stream.missed += ahead - 1
    return True


class GooseSupervisor:
    """Follows every GOOSE control block it is fed; see the module documentation."""

    def __init__(self) -> None:
        self.streams: dict[str, GooseStream] = {}

    def feed(self, pdu: goose.GoosePDU, timestamp: float, eth: Optional[ethernet.EthernetFrame] = None) -> list[Event]:
        """Account for one message received at ``timestamp`` (seconds); returns what it revealed."""
        ref = pdu.gocb_ref
        events: list[Event] = []

        def emit(kind: EventKind, detail: str = "", missed: int = 0) -> None:
            events.append(Event(kind, ref, timestamp, detail, missed))

        stream = self.streams.get(ref)
        accept = True
        if stream is None:
            stream = self.streams[ref] = GooseStream(ref, timestamp, timestamp, pdu)
            emit(EventKind.NEW_STREAM, f"stNum {pdu.st_num} sqNum {pdu.sq_num}, TAL {pdu.time_allowed_to_live} ms")
            if pdu.simulation:
                emit(EventKind.SIMULATION, "simulation bit set")
            if pdu.nds_com:
                emit(EventKind.NDS_COM, "ndsCom set")
        else:
            if stream.timed_out:
                stream.timed_out = False
                emit(EventKind.RESUMED, f"after {timestamp - stream.last_seen:.3f} s")
            _compare_goose_config(stream.last, pdu, emit)
            accept = _follow_goose(stream, pdu, emit)
        # Once per episode: when the stream starts inconsistent or becomes so.
        if not _consistent(pdu) and (stream.last is pdu or _consistent(stream.last)):
            emit(EventKind.INCONSISTENT, f"numDatSetEntries {pdu.num_dat_set_entries}, {len(pdu.all_data)} values")
        stream.messages += 1
        stream.last_seen = timestamp
        if accept:
            stream.last = pdu
            stream.recent.append(pdu.sq_num)
            if eth is not None:
                stream.app_id, stream.src_mac = eth.app_id, eth.src_mac
        _count(stream, events)
        return events

    def check(self, now: float) -> list[Event]:
        """``TIMEOUT`` for each stream silent for longer than its timeAllowedtoLive (once per silence)."""
        events = []
        for stream in self.streams.values():
            if not stream.timed_out and now > stream.deadline:
                stream.timed_out = True
                event = Event(EventKind.TIMEOUT, stream.gocb_ref, now,
                              f"nothing for {now - stream.last_seen:.3f} s (TAL {stream.last.time_allowed_to_live} ms)")
                stream.events[EventKind.TIMEOUT] += 1
                events.append(event)
        return events


# --- Sampled Values ----------------------------------------------------------


_SMP_MOD_PER_SECOND = 1


@dataclass
class SvStreamState:
    """What an :class:`SvSupervisor` knows of one svID."""

    sv_id: str
    first_seen: float
    last_seen: float
    smp_cnt: int
    conf_rev: int
    smp_synch: int
    dat_set: Optional[str]
    app_id: Optional[int] = None
    src_mac: Optional[str] = None
    samples: int = 0
    missed: int = 0
    max_seen: int = 0
    wrapped: bool = False
    timed_out: bool = False
    events: Counter[EventKind] = field(default_factory=_counts)
    recent: deque[int] = field(default_factory=_recent, repr=False)  # counters last accepted


class SvSupervisor:
    """Follows every SV stream it is fed; see the module documentation.

    ``sample_rate`` (samples per second, where smpCnt wraps) applies to every
    stream, ``sample_rates`` to some svIDs. ``timeout`` is how long a stream
    may stay silent before a ``TIMEOUT`` (seconds; ``None`` never).
    """

    def __init__(self, sample_rate: Optional[int] = None, *, sample_rates: Optional[dict[str, int]] = None,
                 timeout: Optional[float] = 0.1) -> None:
        self.sample_rate = sample_rate
        self.sample_rates = dict(sample_rates or {})
        self.timeout = timeout
        self.streams: dict[str, SvStreamState] = {}

    def wrap(self, stream: SvStreamState, asdu: sv.SvAsdu) -> Optional[int]:
        """The value smpCnt wraps at for this stream, if known."""
        rate = self.sample_rates.get(stream.sv_id, self.sample_rate)
        if rate:
            return rate
        if asdu.smp_rate and asdu.smp_mod == _SMP_MOD_PER_SECOND:
            return asdu.smp_rate
        return stream.max_seen + 1 if stream.wrapped else None

    def feed(self, pdu: sv.SvPDU, timestamp: float, eth: Optional[ethernet.EthernetFrame] = None) -> list[Event]:
        """Account for one frame received at ``timestamp`` (seconds); returns what it revealed."""
        events: list[Event] = []
        for asdu in pdu.asdus:
            events += self._feed_asdu(asdu, timestamp, eth)
        return events

    def _feed_asdu(self, asdu: sv.SvAsdu, timestamp: float, eth: Optional[ethernet.EthernetFrame]) -> list[Event]:
        key = asdu.sv_id
        events: list[Event] = []

        def emit(kind: EventKind, detail: str = "", missed: int = 0) -> None:
            events.append(Event(kind, key, timestamp, detail, missed))

        stream = self.streams.get(key)
        accept = True
        if stream is None:
            stream = self.streams[key] = SvStreamState(
                key, timestamp, timestamp, asdu.smp_cnt, asdu.conf_rev, asdu.smp_synch, asdu.dat_set,
            )
            emit(EventKind.NEW_STREAM, f"smpCnt {asdu.smp_cnt}, confRev {asdu.conf_rev}, smpSynch {asdu.smp_synch}")
        else:
            if stream.timed_out:
                stream.timed_out = False
                emit(EventKind.RESUMED, f"after {timestamp - stream.last_seen:.3f} s")
            changes = [
                f"{name} {a} -> {b}"
                for name, a, b in (("confRev", stream.conf_rev, asdu.conf_rev), ("datSet", stream.dat_set, asdu.dat_set))
                if a != b
            ]
            if changes:
                emit(EventKind.CONFIG_CHANGED, ", ".join(changes))
            if asdu.smp_synch != stream.smp_synch:
                emit(EventKind.SYNCH_CHANGED, f"smpSynch {stream.smp_synch} -> {asdu.smp_synch}")
            stream.conf_rev, stream.dat_set, stream.smp_synch = asdu.conf_rev, asdu.dat_set, asdu.smp_synch
            accept = self._follow(stream, asdu, emit)
        stream.samples += 1
        stream.last_seen = timestamp
        if accept:
            stream.smp_cnt = asdu.smp_cnt
            stream.max_seen = max(stream.max_seen, asdu.smp_cnt)
            stream.recent.append(asdu.smp_cnt)
            if eth is not None:
                stream.app_id, stream.src_mac = eth.app_id, eth.src_mac
        _count(stream, events)
        return events

    def _follow(self, stream: SvStreamState, asdu: sv.SvAsdu, emit: _Emit) -> bool:
        """Classify smpCnt against the last accepted one; True if it becomes the reference."""
        prev, cnt = stream.smp_cnt, asdu.smp_cnt
        wrap = self.wrap(stream, asdu)
        if wrap is None and prev - cnt > REORDER_WINDOW:
            # First wrap of a stream of unknown rate: the highest count seen gives the rate.
            stream.wrapped = True
            wrap = stream.max_seen + 1
        if wrap is not None and max(prev, cnt) < wrap:
            # Signed distance modulo the wrap: half a second ahead or more is taken as behind.
            ahead = (cnt - prev) % wrap
            if ahead >= wrap // 2:
                ahead -= wrap
        else:
            ahead = cnt - prev
        if ahead <= 0:
            if -ahead <= REORDER_WINDOW:
                return _late(stream, cnt, f"smpCnt {cnt}", prev, emit)
            emit(EventKind.RESTART, f"smpCnt {prev} -> {cnt}")
            stream.recent.clear()
            return True
        if ahead > 1:
            at = f" (wrap at {wrap})" if cnt < prev else ""
            emit(EventKind.GAP, f"smpCnt {prev} -> {cnt}{at}", ahead - 1)
            stream.missed += ahead - 1
        return True

    def check(self, now: float) -> list[Event]:
        """``TIMEOUT`` for each stream silent for longer than ``timeout`` (once per silence)."""
        if self.timeout is None:
            return []
        events = []
        for stream in self.streams.values():
            if not stream.timed_out and now - stream.last_seen > self.timeout:
                stream.timed_out = True
                stream.events[EventKind.TIMEOUT] += 1
                events.append(Event(EventKind.TIMEOUT, stream.sv_id, now, f"nothing for {now - stream.last_seen:.3f} s"))
        return events


# --- Both, from raw frames ---------------------------------------------------


def _ethertype(raw: bytes) -> Optional[int]:
    if len(raw) < 14:
        return None
    ethertype = int.from_bytes(raw[12:14], "big")
    if ethertype == ethernet.ETHERTYPE_VLAN and len(raw) >= 18:
        ethertype = int.from_bytes(raw[16:18], "big")
    return ethertype


class BusSupervisor:
    """A :class:`GooseSupervisor` and an :class:`SvSupervisor` fed with raw Ethernet frames.

    ``malformed`` counts, per protocol, the GOOSE or SV frames that do not
    decode (truncated, bad length, invalid PDU); other ethertypes are ignored.
    """

    def __init__(self, goose_supervisor: Optional[GooseSupervisor] = None,
                 sv_supervisor: Optional[SvSupervisor] = None) -> None:
        self.goose = goose_supervisor or GooseSupervisor()
        self.sv = sv_supervisor or SvSupervisor()
        self.frames: Counter[str] = Counter()
        self.malformed: Counter[str] = Counter()

    def feed(self, frame: CapturedFrame) -> list[Event]:
        """Account for one captured frame; first reports the streams that timed out before it."""
        events = self.check(frame.timestamp)
        ethertype = _ethertype(frame.data)
        if ethertype == ethernet.ETHERTYPE_GOOSE:
            self.frames["goose"] += 1
            try:
                decoded_goose = goose.decode_goose_frame(frame.data)
            except ber.BerError:
                decoded_goose = None
            if decoded_goose is None:
                self.malformed["goose"] += 1
            else:
                events += self.goose.feed(decoded_goose[1], frame.timestamp, decoded_goose[0])
        elif ethertype == ethernet.ETHERTYPE_SV:
            self.frames["sv"] += 1
            try:
                decoded_sv = sv.decode_sv_frame(frame.data)
            except ber.BerError:
                decoded_sv = None
            if decoded_sv is None:
                self.malformed["sv"] += 1
            else:
                events += self.sv.feed(decoded_sv[1], frame.timestamp, decoded_sv[0])
        else:
            self.frames["other"] += 1
        return events

    def check(self, now: float) -> list[Event]:
        return self.goose.check(now) + self.sv.check(now)

    def summary(self) -> list[str]:
        """One line per stream, then the frame counts."""
        lines = []
        for g in self.goose.streams.values():
            lines.append(f"GOOSE {g.gocb_ref} APPID {_hex(g.app_id)} from {g.src_mac}: {g.messages} messages, "
                         f"stNum {g.last.st_num}, {g.missed} missed{_event_counts(g.events)}")
        for s in self.sv.streams.values():
            span = s.last_seen - s.first_seen
            rate = f", {(s.samples - 1) / span:.0f} samples/s" if span > 0 and s.samples > 1 else ""
            lines.append(f"SV {s.sv_id} APPID {_hex(s.app_id)} from {s.src_mac}: {s.samples} samples{rate}, "
                         f"{s.missed} missed{_event_counts(s.events)}")
        frames = ", ".join(f"{n} {kind}" for kind, n in sorted(self.frames.items()))
        bad = ", ".join(f"{n} {kind}" for kind, n in sorted(self.malformed.items()))
        lines.append(f"frames: {frames or 'none'}" + (f"; malformed: {bad}" if bad else ""))
        return lines


def _hex(value: Optional[int]) -> str:
    return "?" if value is None else f"0x{value:04x}"


def _event_counts(events: Counter[EventKind]) -> str:
    shown = [f"{n} {kind.value}" for kind, n in events.items() if kind is not EventKind.NEW_STREAM]
    return f" ({', '.join(shown)})" if shown else ""


# --- Command line ------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """``open61850-supervise``: supervise the GOOSE and SV streams of a capture file or an interface."""
    import argparse
    import sys
    import time

    from . import pcap

    parser = argparse.ArgumentParser(
        prog="open61850-supervise",
        description="Supervise the GOOSE and SV streams of a pcap/pcapng file, or live on an interface (Linux, root).",
    )
    parser.add_argument("source", nargs="+", help="capture files, or one interface name with --live")
    parser.add_argument("--live", action="store_true", help="capture on the interface named by SOURCE")
    parser.add_argument("--events", action="store_true", help="print every event of a file (always on with --live)")
    parser.add_argument("--quiet-new", action="store_true", help="do not print the first message of each stream")
    parser.add_argument("--sample-rate", type=int, help="samples per second, where smpCnt wraps (default: learnt)")
    parser.add_argument("--sv-timeout", type=float, default=0.1, help="silence before an SV timeout, in seconds")
    parser.add_argument("--duration", type=float, help="with --live, stop after this many seconds")
    args = parser.parse_args(argv)

    bus = BusSupervisor(sv_supervisor=SvSupervisor(args.sample_rate, timeout=args.sv_timeout))
    printed = args.events or args.live

    def show(events: list[Event]) -> None:
        for event in events:
            if printed and not (args.quiet_new and event.kind is EventKind.NEW_STREAM):
                print(event, flush=args.live)

    status = 0
    if args.live:
        from .capture import PacketCapture

        if len(args.source) != 1:
            parser.error("--live takes one interface")
        end = None if args.duration is None else time.monotonic() + args.duration
        try:
            with PacketCapture(args.source[0], outgoing=False) as cap:
                while end is None or time.monotonic() < end:
                    frame = cap.recv()
                    show(bus.check(time.time()) if frame is None else bus.feed(frame))
                stats = cap.stats()
        except KeyboardInterrupt:
            stats = None
        for line in bus.summary():
            print(line)
        if stats is not None:
            print(f"kernel: {stats.received} received, {stats.dropped} dropped")
        return 0

    frames = itertools.chain.from_iterable(pcap.read_pcap(path) for path in args.source)
    try:
        for frame in frames:
            show(bus.feed(frame))
    except (OSError, pcap.PcapError) as exc:
        print(f"open61850-supervise: {exc}", file=sys.stderr)
        status = 1
    for line in bus.summary():
        print(line)
    return status


if __name__ == "__main__":
    raise SystemExit(main())

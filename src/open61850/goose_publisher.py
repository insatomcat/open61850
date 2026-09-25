# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""GOOSE publication with the IEC 61850-8-1 retransmission scheme.

A :class:`GoosePublisher` sends the data set values of one GOOSE control
block. :meth:`GoosePublisher.publish` makes a new state: stNum + 1, sqNum 0,
``t`` = now, sent at once; the message is then repeated after
``min_time_ms``, twice that, four times... up to ``max_time_ms``, then every
``max_time_ms``, sqNum counting each repetition. timeAllowedtoLive is
``tal_factor`` times the wait until the next message (3, as libiec61850
does), so a subscriber declares the stream lost after three missed
messages.

::

    control = GooseControl("IED01_LD0/LLN0$GO$gcbTrip", "IED01_LD0/LLN0$DS_TRIP", app_id=0x0001,
                           dst_mac="01:0c:cd:01:00:01", src_mac="02:00:00:00:00:01")
    with GoosePublisher("eth1", control, [BoolData(False)]) as pub:
        pub.start()
        ...
        pub.publish([BoolData(True)])   # trip

Linux, AF_PACKET (root or CAP_NET_RAW), unless ``send`` is given.
``open61850-goose`` (``python -m open61850.goose_publisher``) publishes from
the command line, with new values read from standard input.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from . import goose
from .data import BoolData, FloatData, IECData, IntData, VisibleStringData

__all__ = [
    "GooseControl",
    "GoosePublisher",
    "retransmission_intervals",
    "parse_values",
    "main",
]

_UINT32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class GooseControl:
    """What a GOOSE control block and its GSE address give: identity, addresses, timing."""

    gocb_ref: str
    dat_set: str
    app_id: int
    dst_mac: str
    src_mac: str
    go_id: Optional[str] = None
    conf_rev: int = 1
    vlan_id: Optional[int] = None
    vlan_priority: Optional[int] = None
    min_time_ms: int = 4
    max_time_ms: int = 1000
    tal_factor: int = 3
    simulation: bool = False
    nds_com: bool = False
    time_quality: int = 0

    def __post_init__(self) -> None:
        if not 0 < self.min_time_ms <= self.max_time_ms:
            raise ValueError("need 0 < min_time_ms <= max_time_ms")
        if self.tal_factor < 1:
            raise ValueError("tal_factor must be at least 1")


def retransmission_intervals(min_time_ms: int, max_time_ms: int) -> Iterator[int]:
    """Waits after each message of a state, in ms: min, 2 min, 4 min... then max for ever."""
    interval = min_time_ms
    while True:
        yield min(interval, max_time_ms)
        interval *= 2


class GoosePublisher:
    """Publishes one GOOSE control block from ``iface`` (or through ``send``)."""

    def __init__(self, iface: str, control: GooseControl, values: Sequence[IECData], *,
                 send: Optional[Callable[[bytes], object]] = None) -> None:
        self.iface = iface
        self.control = control
        self._values = list(values)
        self._send = send
        self._sock: Optional[socket.socket] = None
        self._cond = threading.Condition()
        self._thread: Optional[threading.Thread] = None
        self._stopping = False
        self._changed = False
        self.st_num = 0
        self.sq_num = 0
        self._t = datetime.now(timezone.utc)
        self.frames_sent = 0
        self.send_errors = 0

    # --- state -----------------------------------------------------------------

    def frame(self, time_allowed_to_live: int) -> bytes:
        """The frame of the current stNum and sqNum."""
        c = self.control
        pdu = goose.GoosePDU(
            gocb_ref=c.gocb_ref, time_allowed_to_live=time_allowed_to_live, dat_set=c.dat_set, go_id=c.go_id,
            timestamp=self._t, st_num=self.st_num, sq_num=self.sq_num, simulation=c.simulation,
            conf_rev=c.conf_rev, nds_com=c.nds_com, num_dat_set_entries=len(self._values),
            all_data=list(self._values), time_quality=c.time_quality,
        )
        return goose.encode_goose_frame(pdu, dst_mac=c.dst_mac, src_mac=c.src_mac, app_id=c.app_id,
                                        vlan_id=c.vlan_id, vlan_priority=c.vlan_priority)

    @property
    def values(self) -> list[IECData]:
        with self._cond:
            return list(self._values)

    def publish(self, values: Sequence[IECData]) -> None:
        """A new state: sent at once, then repeated fast, then slower."""
        values = list(values)
        with self._cond:
            if len(values) != len(self._values):
                raise ValueError(f"the data set has {len(self._values)} entries, got {len(values)}")
            self._values = values
            self._changed = True
            self._cond.notify()

    def _new_state(self) -> None:
        self.st_num = 1 if self.st_num == _UINT32_MAX else self.st_num + 1
        self.sq_num = 0
        self._t = datetime.now(timezone.utc)

    def _next_sq(self) -> None:
        self.sq_num = 1 if self.sq_num == _UINT32_MAX else self.sq_num + 1

    # --- sending ---------------------------------------------------------------

    def start(self) -> None:
        """Send the first state (stNum 1) and keep repeating it from a thread."""
        if self._thread is not None:
            raise RuntimeError("already started")
        if self._send is None:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)  # type: ignore[attr-defined]
            try:
                sock.bind((self.iface, 0))
            except OSError:
                sock.close()
                raise
            self._sock = sock
            self._send = sock.send
        self._stopping = False
        self._changed = True  # the first state
        self._thread = threading.Thread(target=self._run, name="goose-publisher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with self._cond:
            self._stopping = True
            self._cond.notify()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None
            self._send = None

    def _transmit(self, interval_ms: int) -> None:
        frame = self.frame(self.control.tal_factor * interval_ms)
        assert self._send is not None
        try:
            self._send(frame)
            self.frames_sent += 1
        except OSError:
            self.send_errors += 1

    def _run(self) -> None:
        c = self.control
        intervals = retransmission_intervals(c.min_time_ms, c.max_time_ms)
        due = time.monotonic()
        with self._cond:
            while not self._stopping:
                if self._changed:
                    self._changed = False
                    self._new_state()
                    intervals = retransmission_intervals(c.min_time_ms, c.max_time_ms)
                    due = time.monotonic()
                wait = due - time.monotonic()
                if wait > 0 and not self._changed:
                    self._cond.wait(wait)
                    continue
                interval = next(intervals)
                self._transmit(interval)
                due += interval / 1000
                self._next_sq()

    def __enter__(self) -> GoosePublisher:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


# --- command line ------------------------------------------------------------


def parse_values(text: str) -> list[IECData]:
    """``true,false,12,-3,0.5,'text'``: booleans, integers, floats and quoted visible strings."""
    values: list[IECData] = []
    for item in (part.strip() for part in text.split(",")):
        lowered = item.lower()
        if lowered in ("true", "false"):
            values.append(BoolData(lowered == "true"))
        elif len(item) >= 2 and item[0] == item[-1] and item[0] in "'\"":
            values.append(VisibleStringData(item[1:-1]))
        else:
            try:
                values.append(IntData(int(item, 0)))
            except ValueError:
                try:
                    values.append(FloatData(float(item)))
                except ValueError:
                    raise ValueError(f"cannot read {item!r} as a value") from None
    return values


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="open61850-goose",
        description="Publish one GOOSE control block; each line on standard input is a new state (same syntax as VALUES).",
    )
    parser.add_argument("iface")
    parser.add_argument("src_mac")
    parser.add_argument("dst_mac")
    parser.add_argument("gocb_ref", help="LD/LLN0$GO$name")
    parser.add_argument("dat_set", help="LD/LLN0$DSName")
    parser.add_argument("values", help="initial values: true,false,12,0.5,'text'")
    parser.add_argument("--appid", type=lambda t: int(t, 0), required=True)
    parser.add_argument("--go-id")
    parser.add_argument("--conf-rev", type=int, default=1)
    parser.add_argument("--vlan-id", type=int)
    parser.add_argument("--vlan-priority", type=int, default=4)
    parser.add_argument("--min-time", type=int, default=4, help="first repetition, ms (default 4)")
    parser.add_argument("--max-time", type=int, default=1000, help="steady repetition, ms (default 1000)")
    parser.add_argument("--simulation", action="store_true")
    parser.add_argument("--duration", type=float, help="stop after this many seconds instead of at end of input")
    args = parser.parse_args(argv)
    control = GooseControl(
        args.gocb_ref, args.dat_set, args.appid, args.dst_mac, args.src_mac, go_id=args.go_id, conf_rev=args.conf_rev,
        vlan_id=args.vlan_id, vlan_priority=args.vlan_priority if args.vlan_id is not None else None,
        min_time_ms=args.min_time, max_time_ms=args.max_time, simulation=args.simulation,
    )
    with GoosePublisher(args.iface, control, parse_values(args.values)) as publisher:
        publisher.start()
        print(f"open61850-goose: {args.gocb_ref} APPID 0x{args.appid:04x} on {args.iface}, stNum 1", file=sys.stderr)
        try:
            if args.duration is not None:
                time.sleep(args.duration)
            else:
                for line in sys.stdin:
                    if line.strip():
                        publisher.publish(parse_values(line))
                        print("open61850-goose: new state", file=sys.stderr)
        except KeyboardInterrupt:
            pass
        except ValueError as exc:
            print(f"open61850-goose: {exc}", file=sys.stderr)
            return 1
    print(f"open61850-goose: {publisher.frames_sent} frames sent, {publisher.send_errors} errors", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

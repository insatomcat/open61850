# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for open61850.goose_publisher, checked with open61850.supervision."""

from __future__ import annotations

import itertools
import threading
import time

import pytest

from open61850 import goose
from open61850.data import BoolData, FloatData, IntData, VisibleStringData
from open61850.goose_publisher import GooseControl, GoosePublisher, parse_values, retransmission_intervals
from open61850.supervision import EventKind, GooseSupervisor

CONTROL = GooseControl("IED01_LD0/LLN0$GO$gcbTrip", "IED01_LD0/LLN0$DS_TRIP", app_id=0x0001,
                       dst_mac="01:0c:cd:01:00:01", src_mac="02:00:00:00:00:01", go_id="TRIP", conf_rev=3,
                       vlan_id=10, vlan_priority=4, min_time_ms=10, max_time_ms=80)


class Recorder:
    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.lock = threading.Lock()

    def __call__(self, frame: bytes) -> None:
        with self.lock:
            self.frames.append((time.monotonic(), frame))

    def decoded(self) -> list[tuple[float, goose.GoosePDU]]:
        with self.lock:
            return [(t, goose.decode_goose_frame(f)[1]) for t, f in self.frames]


def test_intervals() -> None:
    assert list(itertools.islice(retransmission_intervals(4, 1000), 10)) == [4, 8, 16, 32, 64, 128, 256, 512, 1000, 1000]
    assert list(itertools.islice(retransmission_intervals(5, 5), 3)) == [5, 5, 5]
    with pytest.raises(ValueError):
        GooseControl("a", "b", 1, "01:0c:cd:01:00:01", "02:00:00:00:00:01", min_time_ms=10, max_time_ms=5)


def test_retransmission_scheme_and_supervision() -> None:
    recorder = Recorder()
    with GoosePublisher("unused", CONTROL, [BoolData(False), IntData(0)], send=recorder) as pub:
        pub.start()
        time.sleep(0.35)
        pub.publish([BoolData(True), IntData(7)])
        time.sleep(0.35)
    messages = recorder.decoded()
    states = [(m.st_num, m.sq_num) for _t, m in messages]
    second = states.index((2, 0))
    assert states[:second] == [(1, n) for n in range(second)]
    assert states[second:] == [(2, n) for n in range(len(states) - second)]
    # waits after sqNum 0, 1, 2, 3...: 10, 20, 40, 80, 80 ms, on a schedule that does not drift
    # (a late message does not delay the next ones); TAL three times the wait
    offsets = [(t - messages[second][0]) * 1000 for t, _m in messages[second:]]
    # Never early; the upper bound is loose for the scheduling jitter of CI machines.
    for offset, nominal in zip(offsets[1:], [10, 30, 70, 150, 230]):
        assert nominal - 1 <= offset <= nominal + 150
    assert [m.time_allowed_to_live for _t, m in messages[second:second + 5]] == [30, 60, 120, 240, 240]
    first = messages[second][1]
    assert (first.gocb_ref, first.dat_set, first.go_id, first.conf_rev) == (CONTROL.gocb_ref, CONTROL.dat_set, "TRIP", 3)
    assert first.all_data == [BoolData(True), IntData(7)] and first.num_dat_set_entries == 2
    assert messages[second + 1][1].timestamp == first.timestamp != messages[0][1].timestamp  # t of the state change

    supervisor = GooseSupervisor()
    events = []
    for t, message in messages:
        events += supervisor.check(t) + supervisor.feed(message, t)
    # No sequence anomaly. A loaded machine (CI) can send a fast repetition after its TAL:
    # the supervisor then rightly reports a timeout, which is the Python thread's limit.
    timing = {EventKind.TIMEOUT, EventKind.RESUMED}
    assert [e.kind for e in events if e.kind not in timing] == [EventKind.NEW_STREAM, EventKind.STATE_CHANGE]
    assert pub.frames_sent == len(messages) and pub.send_errors == 0


def test_publish_checks_and_frame() -> None:
    pub = GoosePublisher("unused", CONTROL, [BoolData(False)], send=lambda _f: None)
    with pytest.raises(ValueError, match="1 entries"):
        pub.publish([BoolData(True), BoolData(False)])
    eth, pdu = goose.decode_goose_frame(pub.frame(123))
    assert (eth.app_id, eth.vlan_id, eth.vlan_priority, pdu.time_allowed_to_live) == (1, 10, 4, 123)


def test_parse_values() -> None:
    assert parse_values("true, FALSE, 12, -0x10, 0.5, 'a b'") == [
        BoolData(True), BoolData(False), IntData(12), IntData(-16), FloatData(0.5), VisibleStringData("a b"),
    ]
    with pytest.raises(ValueError):
        parse_values("maybe")


def test_send_now_sends_from_the_caller_then_the_thread_repeats() -> None:
    recorder = Recorder()
    with GoosePublisher("unused", CONTROL, [BoolData(False)], send=recorder) as pub:
        pub.publish([BoolData(True)], send_now=True)  # not started: the thread will send it
        assert recorder.decoded() == []
        pub.start()
        time.sleep(0.05)
        count = len(recorder.decoded())
        pub.publish([BoolData(False)], send_now=True)
        sent = recorder.decoded()
        # the new state went out before publish returned, from this thread
        assert len(sent) == count + 1
        assert (sent[-1][1].st_num, sent[-1][1].sq_num, sent[-1][1].all_data) == (2, 0, [BoolData(False)])
        time.sleep(0.2)
    messages = [m for _t, m in recorder.decoded()[count:]]
    assert [(m.st_num, m.sq_num) for m in messages[:4]] == [(2, 0), (2, 1), (2, 2), (2, 3)]
    # Never early on the schedule counted from the first message (10 ms, then 30 ms); a late runner
    # makes the next ones leave at once to catch up, as in test_retransmission_scheme_and_supervision.
    times = [t for t, _m in recorder.decoded()[count:count + 3]]
    assert times[1] - times[0] >= 0.0095 and times[2] - times[0] >= 0.0295

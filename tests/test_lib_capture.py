# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""iec61850.capture: BPF program and VLAN restoration everywhere, a real AF_PACKET capture on Linux."""

from __future__ import annotations

import socket
import struct
import sys
import time

import pytest

from iec61850 import capture
from iec61850.capture import ethertype_filter, run_filter

DST = bytes.fromhex("010ccd010001")
SRC = bytes.fromhex("020000000001")


def _frame(ethertype: int, vlan: int | None = None, body: bytes = b"\x00\x01\x00\x08\x00\x00\x00\x00") -> bytes:
    tag = struct.pack("!HH", 0x8100, (4 << 13) | vlan) if vlan is not None else b""
    return DST + SRC + tag + ethertype.to_bytes(2, "big") + body


@pytest.mark.parametrize(
    ("frame", "accepted"),
    [
        (_frame(0x88B8), True),
        (_frame(0x88BA), True),
        (_frame(0x88BA, vlan=105), True),
        (_frame(0x88B8, vlan=305), True),
        (_frame(0x0800), False),
        (_frame(0x0800, vlan=105), False),
        (_frame(0x88B9), False),
        (DST + SRC, False),  # too short for the ethertype
    ],
)
def test_ethertype_filter(frame: bytes, accepted: bool) -> None:
    assert bool(run_filter(ethertype_filter((0x88B8, 0x88BA)), frame)) is accepted


def test_filter_on_one_ethertype() -> None:
    program = ethertype_filter((0x88BA,))
    assert run_filter(program, _frame(0x88BA, vlan=1))
    assert not run_filter(program, _frame(0x88B8, vlan=1))


def _block(packets: list[tuple[bytes, int, int, int, bool]]) -> bytes:
    """A TPACKET_V3 block: (frame as the kernel stores it, status, tci, tpid, outgoing) per packet."""
    first = 48
    body = b""
    for i, (data, status, tci, tpid, outgoing) in enumerate(packets):
        mac = 48 + 20 + 2  # header, sockaddr_ll, then the frame
        size = (mac + len(data) + 15) // 16 * 16
        next_offset = size if i < len(packets) - 1 else 0
        header = struct.pack("=IIIIIIHHIIHH", next_offset, 1790000000 + i, 500_000_000, len(data), len(data), status, mac, mac + 14, 0, tci, tpid, 0)
        header += bytes(48 - len(header))
        sll = struct.pack("=HHiHBB8s", 17, 0, 1, 1, capture.PACKET_OUTGOING if outgoing else 2, 6, b"")
        packet = header + sll + bytes(mac - 48 - len(sll)) + data
        body += packet + bytes(size - len(packet))
    desc = struct.pack("=IIIII", 3, 0, capture.TP_STATUS_USER, len(packets), first)
    return desc + bytes(first - len(desc)) + body


def test_read_block_restores_tags_and_timestamps() -> None:
    valid = capture.TP_STATUS_VLAN_VALID | capture.TP_STATUS_VLAN_TPID_VALID
    block = _block([
        (_frame(0x88BA), valid, 0x8069, 0x8100, False),  # tag stripped by the NIC
        (_frame(0x88B8, vlan=305), 0, 0, 0, True),  # sent by this host, tag still inline
        (_frame(0x88BA), capture.TP_STATUS_VLAN_VALID, 0, 0, False),  # VLAN 0, priority 0: TCI is 0
    ])
    frames = capture.read_block(block, 0)
    assert [f.data for f in frames] == [
        _frame(0x88BA, vlan=105), _frame(0x88B8, vlan=305), _frame(0x88BA)[:12] + bytes.fromhex("81000000") + _frame(0x88BA)[12:],
    ]
    assert [f.outgoing for f in frames] == [False, True, False]
    assert frames[1].timestamp == pytest.approx(1790000001.5)
    assert [f.outgoing for f in capture.read_block(block, 0, outgoing=False)] == [False, False]


linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET is Linux only")


def _raw_sender() -> socket.socket:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)  # type: ignore[attr-defined]
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    sock.bind(("lo", 0))
    return sock


@linux_only
def test_capture_on_loopback() -> None:
    sender = _raw_sender()
    with sender, capture.PacketCapture("lo", timeout=0.5, outgoing=False, promiscuous=False) as cap:
        frames = [_frame(0x88BA, vlan=105, body=b"\x40\x00\x00\x08" + bytes(4)), _frame(0x0800), _frame(0x88B8)]
        before = time.time()
        for frame in frames:
            sender.send(frame)
        received = []
        while (got := cap.recv()) is not None:
            received.append(got)
        assert [f.data for f in received] == [frames[0], frames[2]]  # VLAN tag restored, IPv4 filtered out
        assert all(before - 1 < f.timestamp < time.time() + 1 for f in received)
        assert not any(f.outgoing for f in received)
        assert cap.stats().received >= 2

        cap.set_ethertypes((0x88B8,))
        for frame in frames:
            sender.send(frame)
        received = []
        while (got := cap.recv()) is not None:
            received.append(got.data)
        assert received == [frames[2]]


@linux_only
def test_processbus_capture_on_lo() -> None:
    import threading

    from processbus_capture import ProcessbusCapture

    sender = _raw_sender()
    mux = ProcessbusCapture("lo")
    goose: list[bytes] = []
    sv: list[bytes] = []
    done = threading.Event()

    def on_goose(_ts: float, raw: bytes) -> None:
        goose.append(raw)

    def on_sv(_header: object, raw: bytes, _ts: float) -> None:
        sv.append(raw)
        done.set()

    unsubscribe_goose = mux.subscribe_goose(on_goose)
    unsubscribe_sv = mux.subscribe_sv(on_sv)
    try:
        deadline = time.time() + 5
        while mux.stats()["bpf_mode"] != "goose+sv" and time.time() < deadline:
            time.sleep(0.02)
        with sender:
            sender.send(_frame(0x88B8, vlan=305))
            sender.send(_frame(0x0800))
            sender.send(_frame(0x88BA, vlan=105))
            assert done.wait(5)
        time.sleep(0.1)
        assert goose == [_frame(0x88B8, vlan=305)] and sv == [_frame(0x88BA, vlan=105)]
        stats = mux.stats()
        assert stats["goose_packets"] == 1 and stats["sv_packets"] == 1
    finally:
        unsubscribe_sv()
        unsubscribe_goose()


@linux_only
def test_processbus_capture_lets_sv_through_only_for_an_sv_subscriber() -> None:
    from processbus_capture import ProcessbusCapture

    sender = _raw_sender()
    mux = ProcessbusCapture("lo")
    goose: list[bytes] = []
    unsubscribe_goose = mux.subscribe_goose(lambda _ts, raw: goose.append(raw))

    def wait_mode(mode: str) -> None:
        deadline = time.time() + 5
        while mux.stats()["bpf_mode"] != mode and time.time() < deadline:
            time.sleep(0.02)
        assert mux.stats()["bpf_mode"] == mode

    try:
        with sender:
            wait_mode("goose")
            sender.send(_frame(0x88BA, vlan=105))
            sender.send(_frame(0x88B8, vlan=305))
            deadline = time.time() + 5
            while not goose and time.time() < deadline:
                time.sleep(0.02)
            assert mux.stats()["packets"] == 1  # the SV frame stayed in the kernel

            sv: list[bytes] = []
            unsubscribe_sv = mux.subscribe_sv(lambda _h, raw, _ts: sv.append(raw))
            wait_mode("goose+sv")
            sender.send(_frame(0x88BA, vlan=105))
            deadline = time.time() + 5
            while not sv and time.time() < deadline:
                time.sleep(0.02)
            unsubscribe_sv()
            assert sv == [_frame(0x88BA, vlan=105)]
    finally:
        unsubscribe_goose()

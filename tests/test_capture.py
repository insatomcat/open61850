# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850.capture: BPF program and VLAN restoration everywhere, a real AF_PACKET capture on Linux."""

from __future__ import annotations

import socket
import struct
import sys
import time

import pytest

from open61850 import capture
from open61850.capture import ethertype_filter, run_filter

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


def _slot_v2(data: bytes, status: int, tci: int, tpid: int, outgoing: bool) -> bytes:
    """A TPACKET_V2 ring slot, as the kernel fills it."""
    mac = 32 + 20 + 14  # header, sockaddr_ll, padding so that the network header is aligned
    header = struct.pack("=IIIHHIIHH4x", capture.TP_STATUS_USER | status, len(data), len(data), mac, mac + 14,
                         1790000007, 250_000_000, tci, tpid)
    sll = struct.pack("=HHiHBB8s", 17, 0, 1, 1, capture.PACKET_OUTGOING if outgoing else 2, 6, b"")
    slot = header + sll + bytes(mac - 32 - len(sll)) + data
    return slot + bytes(2048 - len(slot))


def test_read_frame_v2_restores_tags_and_timestamps() -> None:
    valid = capture.TP_STATUS_VLAN_VALID | capture.TP_STATUS_VLAN_TPID_VALID
    ring = _slot_v2(_frame(0x88BA), valid, 0xA069, 0x8100, False) + _slot_v2(_frame(0x88B8, vlan=305), 0, 0, 0, True)
    first = capture.read_frame_v2(ring, 0)
    assert first is not None
    assert first.data == _frame(0x88BA)[:12] + bytes.fromhex("8100a069") + _frame(0x88BA)[12:]
    assert first.timestamp == pytest.approx(1790000007.25)
    assert not first.outgoing
    second = capture.read_frame_v2(ring, 2048)
    assert second is not None and second.outgoing and second.data == _frame(0x88B8, vlan=305)
    assert capture.read_frame_v2(ring, 2048, outgoing=False) is None


linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET is Linux only")


def _raw_sender() -> socket.socket:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)  # type: ignore[attr-defined]
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    sock.bind(("lo", 0))
    return sock


@linux_only
@pytest.mark.parametrize("low_latency", [False, True], ids=["v3", "v2"])
def test_capture_on_loopback(low_latency: bool) -> None:
    sender = _raw_sender()
    with sender, capture.PacketCapture("lo", timeout=0.5, outgoing=False, promiscuous=False, low_latency=low_latency) as cap:
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
def test_low_latency_hands_each_frame_over_at_once() -> None:
    """Each frame reaches the reader at once (no block timer), and the ring of 256 slots wraps around."""
    sender = _raw_sender()
    with sender, capture.PacketCapture("lo", (0x88BA,), timeout=1.0, outgoing=False, promiscuous=False,
                                       buffer_bytes=0, low_latency=True) as cap:
        delays = []
        for n in range(600):
            sender.send(_frame(0x88BA, body=n.to_bytes(8, "big")))
            got = cap.recv()
            assert got is not None and got.data[-8:] == n.to_bytes(8, "big")
            delays.append(time.time() - got.timestamp)
        assert sorted(delays)[300] < 0.001

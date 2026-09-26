# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Frame capture on Linux with an AF_PACKET socket (no libpcap).

:class:`PacketCapture` receives the Ethernet frames of some ethertypes
(GOOSE and SV by default) on one interface, with kernel timestamps. Like
libpcap it reads a TPACKET_V3 ring shared with the kernel: one poll per
block of frames instead of one system call per frame, which matters at the
~17,000 frames/s of a process bus.

- a classic BPF program keeps only those ethertypes, tagged or not;
- most drivers strip the 802.1Q tag before the socket sees the frame: the
  tag the ring header reports is put back in place, so frames look like the
  wire (what libpcap does);
- the interface is put in promiscuous mode for the socket's lifetime;
- :meth:`PacketCapture.stats` gives received and dropped counts
  (``PACKET_STATISTICS``).

A TPACKET_V3 block reaches user space when it is full or when its timer
expires, and that timer runs on kernel ticks: on a SEAPATH hypervisor
(HZ=250, isolated CPUs) a process bus frame waited 4.3 ms in the median
and up to 9 ms before Python saw it. ``low_latency=True`` reads a
TPACKET_V2 ring instead, cut into frames, each visible as soon as the
kernel wrote it: one poll per frame when frames are sparse, for a
protection that must act on each sample.

Example::

    with PacketCapture("eth1") as cap:
        while True:
            frame = cap.recv()
            if frame is not None:
                print(frame.timestamp, frame.data.hex())

Needs CAP_NET_RAW (root).
"""

from __future__ import annotations

import collections
import ctypes
import mmap
import select
import socket
import struct
from typing import NamedTuple, Optional, Union

from .ethernet import ETHERTYPE_GOOSE, ETHERTYPE_SV, ETHERTYPE_VLAN

__all__ = [
    "CapturedFrame",
    "CaptureStats",
    "ethertype_filter",
    "run_filter",
    "read_block",
    "read_frame_v2",
    "PacketCapture",
]


ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_STATISTICS = 6
PACKET_RX_RING = 5
PACKET_VERSION = 10
TPACKET_V2 = 1
TPACKET_V3 = 2
PACKET_OUTGOING = 4
TP_STATUS_KERNEL = 0
TP_STATUS_USER = 1
SO_ATTACH_FILTER = 26
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6

# tpacket_block_desc: version, offset_to_priv, then tpacket_hdr_v1 (block_status, num_pkts, offset_to_first_pkt)
_BLOCK = struct.Struct("=IIIII")
# tpacket3_hdr: next_offset, sec, nsec, snaplen, len, status, mac, net, then hv1 rxhash, vlan_tci, vlan_tpid
_PACKET = struct.Struct("=IIIIIIHHIIH")
_SLL_PKTTYPE = 48 + 10  # sockaddr_ll.sll_pkttype, after the header aligned to 16
_BLOCK_SIZE = 1 << 18
# tpacket2_hdr: status, len, snaplen, mac, net, sec, nsec, vlan_tci, vlan_tpid, 4 octets of padding
_PACKET_V2 = struct.Struct("=IIIHHIIHH4x")
_SLL_PKTTYPE_V2 = 32 + 10
_FRAME_SIZE_V2 = 2048  # a slot: header, sockaddr_ll, then up to about 1,950 octets of frame

# Classic BPF opcodes
_LDH_ABS = 0x28  # BPF_LD | BPF_H | BPF_ABS
_JEQ_K = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
_RET_K = 0x06  # BPF_RET | BPF_K


class CapturedFrame(NamedTuple):
    timestamp: float  # kernel receive time, seconds since the epoch
    data: bytes  # the frame as on the wire (802.1Q tag restored)
    outgoing: bool  # sent by this host


class CaptureStats(NamedTuple):
    received: int
    dropped: int  # frames the kernel could not queue to the socket


def ethertype_filter(ethertypes: tuple[int, ...]) -> list[tuple[int, int, int, int]]:
    """Classic BPF program accepting ``ethertypes``, with or without one 802.1Q tag.

    When the kernel strips the tag, the ethertype is at offset 12; otherwise
    12 holds 0x8100 and the ethertype is at 16.
    """
    n = len(ethertypes)
    accept = 2 * n + 4  # index of the "accept" instruction
    program: list[tuple[int, int, int, int]] = [(_LDH_ABS, 0, 0, 12)]
    for i, ethertype in enumerate(ethertypes):
        program.append((_JEQ_K, accept - (1 + i) - 1, 0, ethertype))
    reject = 2 * n + 3
    program.append((_JEQ_K, 0, reject - (n + 1) - 1, ETHERTYPE_VLAN))
    program.append((_LDH_ABS, 0, 0, 16))
    for i, ethertype in enumerate(ethertypes):
        program.append((_JEQ_K, accept - (n + 3 + i) - 1, 0, ethertype))
    program.append((_RET_K, 0, 0, 0))
    program.append((_RET_K, 0, 0, 0x40000))
    return program


def run_filter(program: list[tuple[int, int, int, int]], frame: bytes) -> int:
    """Interpret the subset of classic BPF used by :func:`ethertype_filter` (for tests)."""
    pc, acc = 0, 0
    while True:
        code, jt, jf, k = program[pc]
        if code == _LDH_ABS:
            if k + 2 > len(frame):
                return 0
            acc = int.from_bytes(frame[k : k + 2], "big")
            pc += 1
        elif code == _JEQ_K:
            pc += 1 + (jt if acc == k else jf)
        elif code == _RET_K:
            return k
        else:
            raise ValueError(f"unsupported BPF opcode 0x{code:X}")


def _with_tag(data: bytes, status: int, tci: int, tpid: int) -> bytes:
    """Put back the 802.1Q tag the kernel stripped, as the ring header reports it."""
    if not (status & TP_STATUS_VLAN_VALID or tci):
        return data
    if not status & TP_STATUS_VLAN_TPID_VALID:
        tpid = ETHERTYPE_VLAN
    return data[:12] + struct.pack("!HH", tpid, tci) + data[12:]


def read_block(ring: Union[bytes, mmap.mmap], offset: int, outgoing: bool = True) -> list[CapturedFrame]:
    """The frames of one TPACKET_V3 block at ``offset`` in the ring."""
    frames: list[CapturedFrame] = []
    _version, _priv, _status, count, first = _BLOCK.unpack_from(ring, offset)
    pos = offset + first
    for _ in range(count):
        next_offset, sec, nsec, snaplen, _len, status, mac, _net, _hash, tci, tpid = _PACKET.unpack_from(ring, pos)
        is_out = ring[pos + _SLL_PKTTYPE] == PACKET_OUTGOING
        if outgoing or not is_out:
            data = _with_tag(ring[pos + mac : pos + mac + snaplen], status, tci, tpid)
            frames.append(CapturedFrame(sec + nsec * 1e-9, data, is_out))
        pos += next_offset
    return frames


def read_frame_v2(ring: Union[bytes, mmap.mmap], offset: int, outgoing: bool = True) -> Optional[CapturedFrame]:
    """The frame of the TPACKET_V2 slot at ``offset``; None when ``outgoing`` is False and this host sent it."""
    _status_word, _len, snaplen, mac, _net, sec, nsec, tci, tpid = _PACKET_V2.unpack_from(ring, offset)
    is_out = ring[offset + _SLL_PKTTYPE_V2] == PACKET_OUTGOING
    if is_out and not outgoing:
        return None
    data = _with_tag(ring[offset + mac : offset + mac + snaplen], _status_word, tci, tpid)
    return CapturedFrame(sec + nsec * 1e-9, data, is_out)


class PacketCapture:
    def __init__(
        self,
        iface: str,
        ethertypes: tuple[int, ...] = (ETHERTYPE_GOOSE, ETHERTYPE_SV),
        *,
        promiscuous: bool = True,
        buffer_bytes: int = 4 * 1024 * 1024,
        timeout: Optional[float] = 0.05,
        outgoing: bool = True,
        low_latency: bool = False,
    ) -> None:
        """Open the capture; ``recv`` returns None after ``timeout`` seconds without a frame.

        ``buffer_bytes`` is the size of the ring. ``outgoing=False`` drops the
        frames this host sends (on ``lo`` every frame shows up twice otherwise).
        ``low_latency`` hands each frame over at once (TPACKET_V2, see above).
        """
        self.iface = iface
        self.outgoing = outgoing
        self.low_latency = low_latency
        self._timeout_ms = -1 if timeout is None else max(1, int(timeout * 1000))
        self._received = 0
        self._dropped = 0
        self._pending: collections.deque[CapturedFrame] = collections.deque()
        self._blocks = max(2, buffer_bytes // _BLOCK_SIZE)
        self._next_block = 0
        self._frames = _BLOCK_SIZE // _FRAME_SIZE_V2 * self._blocks
        self._next_frame = 0
        self._ring: Optional[mmap.mmap] = None
        # Protocol 0: no frame is queued before the filter is attached and the socket bound.
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        try:
            self.set_ethertypes(ethertypes)
            if low_latency:
                self._sock.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V2)
                # tpacket_req: block size and count, frame size and count.
                req = struct.pack("=4I", _BLOCK_SIZE, self._blocks, _FRAME_SIZE_V2, self._frames)
            else:
                self._sock.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
                # tpacket_req3: block size and count, frame size and count, block timeout (ms),
                # private area size, features. A block goes to user space when full or
                # after the timeout, so the timeout bounds the delivery delay.
                req = struct.pack(
                    "=7I", _BLOCK_SIZE, self._blocks, _FRAME_SIZE_V2, _BLOCK_SIZE // _FRAME_SIZE_V2 * self._blocks,
                    max(1, min(self._timeout_ms, 10)) if self._timeout_ms > 0 else 10, 0, 0,
                )
            self._sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req)
            self._ring = mmap.mmap(
                self._sock.fileno(), _BLOCK_SIZE * self._blocks, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
            )
            if promiscuous:
                mreq = struct.pack("iHH8s", socket.if_nametoindex(iface), PACKET_MR_PROMISC, 0, b"")
                self._sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            self._sock.bind((iface, ETH_P_ALL))
            self._poll = select.poll()
            self._poll.register(self._sock.fileno(), select.POLLIN | select.POLLERR)
        except BaseException:
            self.close()
            raise

    def set_ethertypes(self, ethertypes: tuple[int, ...]) -> None:
        """Replace the kernel filter."""
        program = ethertype_filter(tuple(ethertypes))
        code = b"".join(struct.pack("=HBBI", *insn) for insn in program)
        buf = ctypes.create_string_buffer(code, len(code))
        fprog = struct.pack("@HP", len(program), ctypes.addressof(buf))
        self._sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)

    def fileno(self) -> int:
        return self._sock.fileno()

    def recv(self) -> Optional[CapturedFrame]:
        """Next frame, or None when the timeout expires first."""
        if self._pending:
            return self._pending.popleft()
        polled = False
        while True:
            if self.low_latency:
                frame = self._read_ready_frame()
                if frame is not None:
                    return frame
            elif self._read_ready_blocks():
                return self._pending.popleft()
            if polled:
                return None
            self._poll.poll(self._timeout_ms)
            polled = True

    def _read_ready_blocks(self) -> bool:
        """Copy the frames of every block the kernel handed over, and give the blocks back."""
        ring = self._ring
        assert ring is not None
        while True:
            offset = self._next_block * _BLOCK_SIZE
            if struct.unpack_from("=I", ring, offset + 8)[0] & TP_STATUS_USER == 0:
                return bool(self._pending)
            self._pending.extend(read_block(ring, offset, self.outgoing))
            struct.pack_into("=I", ring, offset + 8, TP_STATUS_KERNEL)
            self._next_block = (self._next_block + 1) % self._blocks

    def _read_ready_frame(self) -> Optional[CapturedFrame]:
        """The next frame the kernel handed over (TPACKET_V2), its slot given back; None if there is none."""
        ring = self._ring
        assert ring is not None
        while True:
            offset = self._next_frame * _FRAME_SIZE_V2
            if struct.unpack_from("=I", ring, offset)[0] & TP_STATUS_USER == 0:
                return None
            frame = read_frame_v2(ring, offset, self.outgoing)
            struct.pack_into("=I", ring, offset, TP_STATUS_KERNEL)
            self._next_frame = (self._next_frame + 1) % self._frames
            if frame is not None:
                return frame

    def stats(self) -> CaptureStats:
        """Cumulative counts (the kernel resets its own on every read)."""
        # tpacket_stats for V2 (packets, drops), tpacket_stats_v3 adds a freeze count.
        size = 8 if self.low_latency else 12
        packets, drops = struct.unpack_from("II", self._sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, size))
        self._received += packets
        self._dropped += drops
        return CaptureStats(self._received, self._dropped)

    def close(self) -> None:
        if self._ring is not None:
            self._ring.close()
            self._ring = None
        self._sock.close()

    def __enter__(self) -> PacketCapture:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

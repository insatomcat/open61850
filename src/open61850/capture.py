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
    "PacketCapture",
]


ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_STATISTICS = 6
PACKET_RX_RING = 5
PACKET_VERSION = 10
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
    ) -> None:
        """Open the capture; ``recv`` returns None after ``timeout`` seconds without a frame.

        ``buffer_bytes`` is the size of the ring. ``outgoing=False`` drops the
        frames this host sends (on ``lo`` every frame shows up twice otherwise).
        """
        self.iface = iface
        self.outgoing = outgoing
        self._timeout_ms = -1 if timeout is None else max(1, int(timeout * 1000))
        self._received = 0
        self._dropped = 0
        self._pending: collections.deque[CapturedFrame] = collections.deque()
        self._blocks = max(2, buffer_bytes // _BLOCK_SIZE)
        self._next_block = 0
        self._ring: Optional[mmap.mmap] = None
        # Protocol 0: no frame is queued before the filter is attached and the socket bound.
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        try:
            self.set_ethertypes(ethertypes)
            self._sock.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
            # tpacket_req3: block size and count, frame size and count, block timeout (ms),
            # private area size, features. A block goes to user space when full or
            # after the timeout, so the timeout bounds the delivery delay.
            req = struct.pack(
                "=7I", _BLOCK_SIZE, self._blocks, 2048, _BLOCK_SIZE // 2048 * self._blocks,
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
            if self._read_ready_blocks():
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

    def stats(self) -> CaptureStats:
        """Cumulative counts (the kernel resets its own on every read)."""
        packets, drops, _freeze = struct.unpack("III", self._sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 12))
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

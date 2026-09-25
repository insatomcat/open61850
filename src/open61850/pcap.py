# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Capture files: pcap and pcapng (Wireshark, tcpdump, dumpcap), with no dependency.

:func:`read_pcap` yields the frames of a file as :class:`~open61850.capture.CapturedFrame`,
the type :class:`~open61850.capture.PacketCapture` returns, so the same code
analyses a live capture or a file, on any OS. :class:`PcapWriter` writes the
classic format with nanosecond timestamps.

Only Ethernet captures are read (link type 1): the one of a process bus. The
pcapng reader follows the sections, the interfaces' timestamp resolution and
offset, and the direction flag of Enhanced Packet Blocks.

Example::

    from open61850 import goose, pcap

    for frame in pcap.read_pcap("bus.pcapng"):
        if (decoded := goose.decode_goose_frame(frame.data)) is not None:
            print(frame.timestamp, decoded[1].gocb_ref, decoded[1].st_num)
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, Optional, Union

from .capture import CapturedFrame

__all__ = [
    "LINKTYPE_ETHERNET",
    "PcapError",
    "read_pcap",
    "PcapWriter",
]


LINKTYPE_ETHERNET = 1

_PCAP_MICRO = 0xA1B2C3D4
_PCAP_NANO = 0xA1B23C4D
_SHB = 0x0A0D0D0A
_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_IDB = 1
_PB = 2  # obsolete Packet Block
_SPB = 3
_EPB = 6
_OPT_END = 0
_OPT_IF_TSRESOL = 9
_OPT_IF_TSOFFSET = 14
_OPT_EPB_FLAGS = 2
_EPB_OUTBOUND = 2  # direction bits 0-1 of epb_flags
_MAX_BLOCK = 16 * 1024 * 1024

Source = Union[str, Path, BinaryIO]


class PcapError(ValueError):
    """The file is not a pcap or pcapng capture of Ethernet frames, or it is truncated."""


def read_pcap(source: Source) -> Iterator[CapturedFrame]:
    """The frames of a pcap or pcapng file (a path or a binary file object), in file order.

    A file cut in the middle of a record (a capture killed while writing)
    yields every complete frame, then raises :class:`PcapError`.
    """
    if isinstance(source, (str, Path)):
        with open(source, "rb") as handle:
            yield from _read(handle)
    else:
        yield from _read(source)


def _read(handle: BinaryIO) -> Iterator[CapturedFrame]:
    head = handle.read(4)
    if len(head) < 4:
        raise PcapError("empty or truncated capture file")
    if int.from_bytes(head, "little") == _SHB:
        yield from _read_pcapng(handle, head)
        return
    for order in "<>":
        magic = struct.unpack(order + "I", head)[0]
        if magic in (_PCAP_MICRO, _PCAP_NANO):
            yield from _read_pcap(handle, order, 1_000_000_000 if magic == _PCAP_NANO else 1_000_000)
            return
    raise PcapError(f"not a pcap or pcapng file (magic {head.hex()})")


def _exact(handle: BinaryIO, size: int, what: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise PcapError(f"truncated {what}: {len(data)} of {size} bytes")
    return data


def _check_link(linktype: int) -> None:
    if linktype != LINKTYPE_ETHERNET:
        raise PcapError(f"link type {linktype} is not Ethernet ({LINKTYPE_ETHERNET})")


def _read_pcap(handle: BinaryIO, order: str, units: int) -> Iterator[CapturedFrame]:
    header = _exact(handle, 20, "pcap header")
    # The upper bits of the link type field carry the FCS length, if any.
    _check_link(struct.unpack(order + "I", header[16:20])[0] & 0x0FFFFFFF)
    record = struct.Struct(order + "IIII")
    while True:
        raw = handle.read(16)
        if not raw:
            return
        if len(raw) < 16:
            raise PcapError(f"truncated record header: {len(raw)} of 16 bytes")
        sec, frac, captured, _original = record.unpack(raw)
        if captured > _MAX_BLOCK:
            raise PcapError(f"record of {captured} bytes: corrupt file")
        yield CapturedFrame(sec + frac / units, _exact(handle, captured, "record"), False)


class _Interface:
    __slots__ = ("linktype", "offset", "snaplen", "units")

    def __init__(self, linktype: int, snaplen: int, units: int, offset: int) -> None:
        self.linktype = linktype
        self.snaplen = snaplen
        self.units = units  # timestamp ticks per second
        self.offset = offset  # seconds added to every timestamp

    def timestamp(self, ticks: int) -> float:
        sec, frac = divmod(ticks, self.units)
        return self.offset + sec + frac / self.units


def _options(body: bytes, order: str) -> Iterator[tuple[int, bytes]]:
    pos = 0
    while pos + 4 <= len(body):
        code, length = struct.unpack_from(order + "HH", body, pos)
        if code == _OPT_END:
            return
        yield code, body[pos + 4 : pos + 4 + length]
        pos += 4 + (length + 3) // 4 * 4


def _interface(body: bytes, order: str) -> _Interface:
    if len(body) < 8:
        raise PcapError("truncated interface description block")
    linktype, _reserved, snaplen = struct.unpack_from(order + "HHI", body)
    units, offset = 1_000_000, 0
    for code, value in _options(body[8:], order):
        if code == _OPT_IF_TSRESOL and value:
            exponent = value[0] & 0x7F
            units = 2**exponent if value[0] & 0x80 else 10**exponent
        elif code == _OPT_IF_TSOFFSET and len(value) == 8:
            offset = struct.unpack(order + "q", value)[0]
    return _Interface(linktype, snaplen, units, offset)


def _read_pcapng(handle: BinaryIO, first: bytes) -> Iterator[CapturedFrame]:
    order = "<"
    interfaces: list[_Interface] = []
    block_type_raw: Optional[bytes] = first
    while True:
        if block_type_raw is None:
            block_type_raw = handle.read(4)
            if not block_type_raw:
                return
            if len(block_type_raw) < 4:
                raise PcapError("truncated block header")
        length_raw = _exact(handle, 4, "block header")
        if int.from_bytes(block_type_raw, "little") == _SHB:
            # The byte order of a section is given by the magic after the length.
            magic = _exact(handle, 4, "section header")
            order = "<" if int.from_bytes(magic, "little") == _BYTE_ORDER_MAGIC else ">"
            if struct.unpack(order + "I", magic)[0] != _BYTE_ORDER_MAGIC:
                raise PcapError("bad pcapng byte-order magic")
            interfaces = []
            total = struct.unpack(order + "I", length_raw)[0]
            _check_block_length(total)
            _exact(handle, total - 12, "section header")
            block_type_raw = None
            continue
        block_type = struct.unpack(order + "I", block_type_raw)[0]
        total = struct.unpack(order + "I", length_raw)[0]
        _check_block_length(total)
        body = _exact(handle, total - 8, "block")[:-4]  # without the trailing length
        block_type_raw = None
        if block_type == _IDB:
            interfaces.append(_interface(body, order))
        elif block_type == _EPB:
            if len(body) < 20:
                raise PcapError("truncated enhanced packet block")
            iface_id, high, low, captured, _original = struct.unpack_from(order + "IIIII", body)
            iface = _lookup(interfaces, iface_id)
            data = body[20 : 20 + captured]
            outgoing = False
            for code, value in _options(body[20 + (captured + 3) // 4 * 4 :], order):
                if code == _OPT_EPB_FLAGS and len(value) == 4:
                    outgoing = struct.unpack(order + "I", value)[0] & 3 == _EPB_OUTBOUND
            yield CapturedFrame(iface.timestamp((high << 32) | low), data, outgoing)
        elif block_type == _SPB:
            iface = _lookup(interfaces, 0)
            original = struct.unpack_from(order + "I", body)[0]
            captured = min(original, iface.snaplen or original, len(body) - 4)
            # A Simple Packet Block has no timestamp.
            yield CapturedFrame(0.0, body[4 : 4 + captured], False)
        elif block_type == _PB:
            iface_id, _drops, high, low, captured, _original = struct.unpack_from(order + "HHIIII", body)
            iface = _lookup(interfaces, iface_id)
            yield CapturedFrame(iface.timestamp((high << 32) | low), body[20 : 20 + captured], False)


def _check_block_length(total: int) -> None:
    if total < 12 or total % 4 or total > _MAX_BLOCK:
        raise PcapError(f"bad pcapng block length {total}")


def _lookup(interfaces: list[_Interface], iface_id: int) -> _Interface:
    if iface_id >= len(interfaces):
        raise PcapError(f"packet on undeclared interface {iface_id}")
    iface = interfaces[iface_id]
    _check_link(iface.linktype)
    return iface


class PcapWriter:
    """Write frames to a classic pcap file (nanosecond timestamps, Ethernet)."""

    def __init__(self, target: Source, snaplen: int = 65535) -> None:
        self._own = isinstance(target, (str, Path))
        self._handle: BinaryIO = open(target, "wb") if isinstance(target, (str, Path)) else target
        self._snaplen = snaplen
        self._handle.write(struct.pack("<IHHiIII", _PCAP_NANO, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET))

    def write(self, frame: Union[CapturedFrame, bytes], timestamp: Optional[float] = None) -> None:
        """Append a frame; ``timestamp`` defaults to the frame's own (0 for bare bytes)."""
        if isinstance(frame, CapturedFrame):
            data = frame.data
            when = frame.timestamp if timestamp is None else timestamp
        else:
            data = bytes(frame)
            when = timestamp or 0.0
        ns = round(when * 1_000_000_000)
        kept = data[: self._snaplen]
        self._handle.write(struct.pack("<IIII", ns // 1_000_000_000, ns % 1_000_000_000, len(kept), len(data)) + kept)

    def close(self) -> None:
        if self._own:
            self._handle.close()
        else:
            self._handle.flush()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

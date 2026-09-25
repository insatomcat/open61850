# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for open61850.pcap.

``editcap_pcapng.json`` holds two files written by Wireshark's editcap from
synthetic frames (see its ``_source``), with nanosecond and microsecond
timestamps.
"""

from __future__ import annotations

import io
import json
import struct

import pytest
from conftest import DATA_DIR

from open61850 import goose, pcap, sv
from open61850.capture import CapturedFrame

EDITCAP = {k: bytes.fromhex(v) for k, v in json.loads((DATA_DIR / "editcap_pcapng.json").read_text()).items() if k != "_source"}


def _check_reference(frames: list[CapturedFrame], first_ts: float) -> None:
    assert len(frames) == 6
    counts = [sv.decode_sv_frame(f.data)[1].asdus[0].smp_cnt for f in frames[:5]]
    assert counts == [0, 1, 2, 3, 4]
    eth, pdu = goose.decode_goose_frame(frames[5].data)
    assert (eth.vlan_id, pdu.st_num, pdu.gocb_ref) == (10, 3, "IED01_LD0/LLN0$GO$gcb1")
    assert frames[0].timestamp == pytest.approx(first_ts, abs=1e-7)
    assert frames[1].timestamp - frames[0].timestamp == pytest.approx(250e-6, abs=2e-6)
    assert frames[5].timestamp == pytest.approx(1790000000.5, abs=1e-7)
    assert not any(f.outgoing for f in frames)


def test_editcap_pcapng_nanoseconds() -> None:
    _check_reference(list(pcap.read_pcap(io.BytesIO(EDITCAP["ns"]))), 1790000000.123456717)


def test_editcap_pcapng_default_microseconds() -> None:
    _check_reference(list(pcap.read_pcap(io.BytesIO(EDITCAP["us"]))), 1790000000.123456)


def test_path_source(tmp_path) -> None:
    path = tmp_path / "bus.pcapng"
    path.write_bytes(EDITCAP["ns"])
    assert len(list(pcap.read_pcap(path))) == len(list(pcap.read_pcap(str(path)))) == 6


def test_writer_round_trip_and_file_objects() -> None:
    frames = list(pcap.read_pcap(io.BytesIO(EDITCAP["ns"])))
    buf = io.BytesIO()
    with pcap.PcapWriter(buf) as writer:
        for frame in frames:
            writer.write(frame)
        writer.write(b"\x01" * 20, 12.5)
    buf.seek(0)
    again = list(pcap.read_pcap(buf))
    assert [f.data for f in again] == [f.data for f in frames] + [b"\x01" * 20]
    assert [f.timestamp for f in again[:-1]] == pytest.approx([f.timestamp for f in frames], abs=1e-9)
    assert again[-1].timestamp == 12.5


def test_writer_snaplen_truncates(tmp_path) -> None:
    path = tmp_path / "cut.pcap"
    with pcap.PcapWriter(path, snaplen=16) as writer:
        writer.write(bytes(range(40)), 1.0)
    assert [f.data for f in pcap.read_pcap(path)] == [bytes(range(16))]


def test_classic_big_endian_microseconds() -> None:
    raw = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    raw += struct.pack(">IIII", 100, 250, 3, 3) + b"abc"
    (frame,) = pcap.read_pcap(io.BytesIO(raw))
    assert frame == CapturedFrame(100.00025, b"abc", False)


def _block(order: str, block_type: int, body: bytes) -> bytes:
    body += bytes(-len(body) % 4)
    total = 12 + len(body)
    return struct.pack(order + "II", block_type, total) + body + struct.pack(order + "I", total)


def _option(order: str, code: int, value: bytes) -> bytes:
    return struct.pack(order + "HH", code, len(value)) + value + bytes(-len(value) % 4)


def _shb(order: str) -> bytes:
    return _block(order, 0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1))


@pytest.mark.parametrize("order", ["<", ">"])
def test_pcapng_options_and_block_kinds(order: str) -> None:
    # Interface 0: timestamps in 2^-10 s, offset 1000 s. Interface 1: default microseconds.
    idb0 = struct.pack(order + "HHI", 1, 0, 0) + _option(order, 9, b"\x8a") + _option(order, 14, struct.pack(order + "q", 1000))
    idb0 += _option(order, 0, b"")
    idb1 = struct.pack(order + "HHI", 1, 0, 4)
    outbound = _option(order, 2, struct.pack(order + "I", 2)) + _option(order, 0, b"")
    epb = struct.pack(order + "IIIII", 0, 0, 512, 3, 3) + b"abc\x00" + outbound
    spb = struct.pack(order + "I", 6) + b"simple\x00\x00"  # snaplen 0 on interface 0: no limit
    old = struct.pack(order + "HHIIII", 1, 0, 0, 2_000_000, 2, 2) + b"pb"
    unknown = _block(order, 0x0BAD, b"skip me!")
    raw = _shb(order) + _block(order, 1, idb0) + _block(order, 1, idb1) + _block(order, 6, epb)
    raw += unknown + _block(order, 3, spb) + _block(order, 2, old)
    frames = list(pcap.read_pcap(io.BytesIO(raw)))
    assert frames == [
        CapturedFrame(1000.5, b"abc", True),
        CapturedFrame(0.0, b"simple", False),
        CapturedFrame(2.0, b"pb", False),
    ]


def test_pcapng_new_section_resets_interfaces() -> None:
    idb = _block("<", 1, struct.pack("<HHI", 1, 0, 0))
    epb = _block("<", 6, struct.pack("<IIIII", 0, 0, 1_000_000, 1, 1) + b"x")
    raw = _shb("<") + idb + epb + _shb("<") + epb
    frames = pcap.read_pcap(io.BytesIO(raw))
    assert next(frames).data == b"x"
    with pytest.raises(pcap.PcapError, match="undeclared interface"):
        next(frames)


def test_non_ethernet_link_is_refused() -> None:
    raw = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113)  # Linux cooked capture
    with pytest.raises(pcap.PcapError, match="not Ethernet"):
        list(pcap.read_pcap(io.BytesIO(raw)))


@pytest.mark.parametrize("name", ["ns", "us"])
def test_truncated_file_yields_complete_frames_then_raises(name: str) -> None:
    raw = EDITCAP[name]
    frames = pcap.read_pcap(io.BytesIO(raw[:-40]))
    assert len([next(frames) for _ in range(5)]) == 5
    with pytest.raises(pcap.PcapError, match="truncated"):
        next(frames)


@pytest.mark.parametrize("raw", [b"", b"\x00\x01", b"GIF89a....", bytes(24)])
def test_not_a_capture(raw: bytes) -> None:
    with pytest.raises(pcap.PcapError):
        list(pcap.read_pcap(io.BytesIO(raw)))

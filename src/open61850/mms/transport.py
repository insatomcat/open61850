# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""ISO transport over TCP: TPKT (RFC 1006) and COTP class 0 (ISO 8073).

Only what an MMS client needs: connection request/confirm, data TPDUs with
segmentation on send and reassembly on receive.
"""

from __future__ import annotations

import socket
import struct
import threading
from typing import Optional

TPKT_VERSION = 3
_CR = 0xE0
_CC = 0xD0
_DR = 0x80
_DT = 0xF0
_EOT = 0x80

# TPDU size parameter: 2^code bytes. 0x0A = 1024, the size IEDs commonly accept.
DEFAULT_TPDU_SIZE_CODE = 0x0A


class TransportError(ConnectionError):
    """TPKT/COTP failure or connection loss."""


def _recv_exact(sock: socket.socket, size: int) -> Optional[bytes]:
    chunks = []
    while size:
        chunk = sock.recv(size)
        if not chunk:
            return None
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def send_tpkt(sock: socket.socket, payload: bytes) -> None:
    length = 4 + len(payload)
    if length > 0xFFFF:
        raise TransportError(f"TPKT too long: {length} bytes")
    sock.sendall(struct.pack("!BBH", TPKT_VERSION, 0, length) + payload)


def recv_tpkt(sock: socket.socket) -> Optional[bytes]:
    """Read one TPKT payload; None when the peer closed the connection."""
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    version, _, length = struct.unpack("!BBH", header)
    if version != TPKT_VERSION or length < 4:
        raise TransportError(f"invalid TPKT header {header.hex()}")
    if length == 4:
        return b""
    payload = _recv_exact(sock, length - 4)
    if payload is None:
        return None
    return payload


def connection_request(
    *,
    src_ref: int = 1,
    tpdu_size_code: int = DEFAULT_TPDU_SIZE_CODE,
    calling_tsap: bytes = b"\x00\x01",
    called_tsap: bytes = b"\x00\x01",
) -> bytes:
    """COTP CR TPDU, class 0."""
    params = (
        bytes([0xC0, 1, tpdu_size_code])
        + bytes([0xC2, len(called_tsap)]) + called_tsap
        + bytes([0xC1, len(calling_tsap)]) + calling_tsap
    )
    fixed = bytes([_CR, 0, 0]) + src_ref.to_bytes(2, "big") + b"\x00"
    body = fixed + params
    return bytes([len(body)]) + body


class IsoConnection:
    """A COTP connection carrying whole TSDUs (the user data of MMS)."""

    def __init__(self, sock: socket.socket, *, tpdu_size: int = 1 << DEFAULT_TPDU_SIZE_CODE) -> None:
        self._sock = sock
        self._tpdu_size = tpdu_size
        self._send_lock = threading.Lock()

    @classmethod
    def connect(
        cls,
        host: str,
        port: int = 102,
        *,
        timeout: float = 10.0,
        calling_tsap: bytes = b"\x00\x01",
        called_tsap: bytes = b"\x00\x01",
    ) -> IsoConnection:
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass  # not a TCP socket (tests use socketpairs)
            send_tpkt(sock, connection_request(calling_tsap=calling_tsap, called_tsap=called_tsap))
            cc = recv_tpkt(sock)
            if cc is None:
                raise TransportError("connection closed while waiting for COTP CC")
            if len(cc) < 2 or cc[1] & 0xF0 != _CC:
                raise TransportError(f"expected COTP CC, got {cc[:8].hex()}")
            tpdu_size = cls._negotiated_tpdu_size(cc)
        except BaseException:
            sock.close()
            raise
        sock.settimeout(None)
        return cls(sock, tpdu_size=tpdu_size)

    @staticmethod
    def _negotiated_tpdu_size(cc: bytes) -> int:
        size = 1 << DEFAULT_TPDU_SIZE_CODE
        offset = 7  # LI, code, dst-ref(2), src-ref(2), class
        while offset + 2 <= len(cc):
            code, length = cc[offset], cc[offset + 1]
            if code == 0xC0 and length == 1 and offset + 2 < len(cc):
                size = 1 << cc[offset + 2]
            offset += 2 + length
        return size

    def send(self, user_data: bytes) -> None:
        """Send one TSDU, split into DT TPDUs of the negotiated size."""
        room = max(1, self._tpdu_size - 3)
        with self._send_lock:
            for start in range(0, max(1, len(user_data)), room):
                chunk = user_data[start : start + room]
                last = start + room >= len(user_data)
                send_tpkt(self._sock, bytes([2, _DT, _EOT if last else 0]) + chunk)

    def recv(self) -> Optional[bytes]:
        """Receive one TSDU; None when the peer closed or disconnected."""
        chunks: list[bytes] = []
        while True:
            payload = recv_tpkt(self._sock)
            if payload is None:
                return None
            if len(payload) < 2:
                raise TransportError(f"TPDU too short: {payload.hex()}")
            code = payload[1] & 0xF0
            if code == _DR:
                return None
            if code != _DT:
                continue
            if len(payload) < 3:
                raise TransportError(f"DT TPDU too short: {payload.hex()}")
            chunks.append(payload[3:])
            if payload[2] & _EOT:
                return b"".join(chunks)

    @property
    def local_address(self) -> Optional[str]:
        """This end's IP address (what IEC 61850 servers record as Owner)."""
        try:
            return self._sock.getsockname()[0]
        except (OSError, IndexError):
            return None

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()

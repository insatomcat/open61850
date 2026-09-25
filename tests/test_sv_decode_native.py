# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850-core's SV decoder accepts what open61850.sv accepts, with the same fields.

Random PDUs and frames, BER forms the encoder never produces (long and
non-minimal lengths, high tags, unknown and repeated fields, fields out of
order), then byte mutations of all of them: both decoders must refuse, or
both accept with the same values.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from open61850 import ber, sv
from open61850.data import decode_utc_time
from open61850.ethernet import mac_to_str

rt = pytest.importorskip("open61850_rt")


def _text(rng: random.Random, n: int) -> str:
    return "".join(chr(rng.randint(0, 127)) for _ in range(n))


def _random_asdu(rng: random.Random) -> sv.SvAsdu:
    maybe = rng.random() < 0.5
    return sv.SvAsdu(
        sv_id=_text(rng, rng.choice([0, 4, 20, 65, 130])),
        smp_cnt=rng.randint(0, 0xFFFF),
        conf_rev=rng.randint(0, 0xFFFFFFFF),
        smp_synch=rng.randint(0, 255),
        sample=bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 8, 64, 72, 13, 200]))),
        dat_set=_text(rng, rng.randint(0, 40)) if maybe else None,
        refr_tm=(datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=rng.randint(0, 0xFFFFFFFF),
                                                                       microseconds=rng.randint(0, 999_999))
                 if rng.random() < 0.3 else None),
        smp_rate=rng.randint(0, 0xFFFF) if maybe else None,
        smp_mod=rng.randint(0, 0xFFFF) if rng.random() < 0.3 else None,
        gm_identity=bytes(rng.getrandbits(8) for _ in range(8)) if rng.random() < 0.3 else None,
    )


def _random_pdu(rng: random.Random) -> bytes:
    pdu = sv.SvPDU([_random_asdu(rng) for _ in range(rng.choice([1, 1, 2, 2, 4, 8]))])
    if rng.random() < 0.2:
        pdu.security = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 20)))
    return sv.encode_sv_pdu(pdu)


def _tlv(rng: random.Random, tag: bytes, content: bytes) -> bytes:
    """A TLV with a length in short, long, or non-minimal long form."""
    n = len(content)
    form = rng.random()
    if form < 0.6 and n < 0x80:
        length = bytes([n])
    elif form < 0.8:
        raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
        length = bytes([0x80 | len(raw)]) + raw
    else:
        width = rng.randint(1, 4) + max(1, (n.bit_length() + 7) // 8)
        length = bytes([0x80 | width]) + n.to_bytes(width, "big")
    return tag + length + content


def _odd_pdu(rng: random.Random) -> bytes:
    """A SavPdu written TLV by TLV, in forms the encoder does not use."""
    asdus = []
    for _ in range(rng.choice([0, 1, 2, 3])):
        fields = [
            _tlv(rng, b"\x80", _text(rng, rng.randint(0, 10)).encode()),
            _tlv(rng, b"\x82", rng.getrandbits(16).to_bytes(2, "big")),
            _tlv(rng, b"\x83", rng.getrandbits(32).to_bytes(4, "big")),
            _tlv(rng, b"\x85", bytes([rng.getrandbits(8)])),
            _tlv(rng, b"\x87", bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 8, 16, 5])))),
        ]
        optional = [
            _tlv(rng, b"\x81", b"LD/LLN0$DS"),
            _tlv(rng, b"\x84", bytes(rng.getrandbits(8) for _ in range(rng.choice([8, 8, 9, 12])))),
            _tlv(rng, b"\x86", rng.getrandbits(16).to_bytes(2, "big")),
            _tlv(rng, b"\x88", rng.getrandbits(16).to_bytes(2, "big")),
            _tlv(rng, b"\x89", bytes(rng.choice([8, 8, 3, 0]))),
            _tlv(rng, b"\x8a", b"\x01"),                 # [10], unknown
            _tlv(rng, b"\xa0", b"\x80\x01\x00"),         # [0] constructed: not svID
            _tlv(rng, b"\x9f\x20", b"\x00"),             # high tag number
            _tlv(rng, b"\x9f\x00", b"\x01\x02"),         # tag [0] in high form: not svID
            _tlv(rng, b"\x82", b"\x00\x07"),             # smpCnt again: the last one wins
        ]
        fields += rng.sample(optional, rng.randint(0, len(optional)))
        if rng.random() < 0.5:
            rng.shuffle(fields)
        asdus.append(_tlv(rng, b"\x30", b"".join(fields)))
    split = rng.randint(0, len(asdus))
    groups = [asdus[:split], asdus[split:]] if rng.random() < 0.3 else [asdus]
    no_asdu = rng.choice([
        len(asdus).to_bytes(1, "big"), bytes(3) + len(asdus).to_bytes(1, "big"), bytes(12) + bytes([len(asdus)]),
        b"\x01" + bytes(9), b"",
    ])
    body = [_tlv(rng, b"\x80", no_asdu)] + [_tlv(rng, b"\xa2", b"".join(g)) for g in groups]
    if rng.random() < 0.3:
        body.append(_tlv(rng, b"\xa1", b"\x04\x00"))
    if rng.random() < 0.3:
        body.append(_tlv(rng, b"\x83", b"\x00"))          # unknown PDU field
    if rng.random() < 0.2:
        body.insert(0, _tlv(rng, b"\x80", bytes(10)))     # noASDU twice: the last one wins
    if rng.random() < 0.5:
        rng.shuffle(body)
    return _tlv(rng, b"\x60", b"".join(body)) + (b"\x00\x00" if rng.random() < 0.2 else b"")


def _mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.choice([1, 1, 1, 2, 4])):
        op = rng.random()
        if not b:
            b.append(rng.getrandbits(8))
        elif op < 0.4:
            b[rng.randrange(len(b))] = rng.getrandbits(8)
        elif op < 0.55:
            i = rng.randrange(len(b))
            b[i] = (b[i] + rng.choice([-1, 1])) & 0xFF
        elif op < 0.7:
            del b[rng.randrange(len(b))]
        elif op < 0.85:
            b.insert(rng.randrange(len(b) + 1), rng.getrandbits(8))
        else:
            del b[rng.randrange(len(b)):]
    return bytes(b)


def _python_pdu(pdu: sv.SvPDU) -> tuple:
    return pdu.security, [
        (a.sv_id, a.dat_set, a.smp_cnt, a.conf_rev, a.refr_tm, a.smp_synch, a.smp_rate, a.sample, a.smp_mod,
         a.gm_identity)
        for a in pdu.asdus
    ]


def _native_pdu(pdu: tuple[Optional[bytes], list[dict[str, Any]]]) -> tuple:
    def text(raw: Optional[bytes]) -> Optional[str]:
        return None if raw is None else raw.decode("ascii", errors="replace")

    def time(t: Optional[tuple[int, int, int]]) -> Optional[datetime]:
        return None if t is None else decode_utc_time(t[0].to_bytes(4, "big") + t[1].to_bytes(3, "big") + bytes([t[2]]))[0]

    security, asdus = pdu
    return security, [
        (text(a["sv_id"]), text(a["dat_set"]), a["smp_cnt"], a["conf_rev"], time(a["refr_tm"]), a["smp_synch"],
         a["smp_rate"], a["sample"], a["smp_mod"], a["gm_identity"])
        for a in asdus
    ]


def _outcome(decode: Callable[[bytes], Any], error: type[Exception], data: bytes) -> Any:
    try:
        return decode(data)
    except error as exc:
        return ("refused", type(exc).__name__)


def _compare_pdu(apdu: bytes) -> bool:
    py = _outcome(sv.decode_sv_pdu, sv.SvDecodeError, apdu)
    rs = _outcome(rt.decode_sv_pdu, ValueError, apdu)
    py_ok, rs_ok = isinstance(py, sv.SvPDU), not (isinstance(rs, tuple) and rs[0] == "refused")
    assert py_ok == rs_ok, f"{apdu.hex()}: Python {py!r}, native {rs!r}"
    if py_ok:
        assert _native_pdu(rs) == _python_pdu(py), apdu.hex()
    return py_ok


def _compare_frame(raw: bytes) -> Optional[bool]:
    py = _outcome(sv.decode_sv_frame, sv.SvDecodeError, raw)
    rs = _outcome(rt.decode_sv_frame, ValueError, raw)
    if py is None or rs is None:
        assert py is None and rs is None, f"{raw.hex()}: Python {py!r}, native {rs!r}"
        return None
    py_ok, rs_ok = isinstance(py, tuple) and py[0] != "refused", rs[0] != "refused"
    assert py_ok == rs_ok, f"{raw.hex()}: Python {py!r}, native {rs!r}"
    if py_ok:
        (frame, pdu), (header, native) = py, rs
        assert (frame.dst_mac, frame.src_mac, frame.vlan_id, frame.vlan_priority, frame.app_id, frame.reserved1,
                frame.reserved2) == (mac_to_str(header["dst_mac"]), mac_to_str(header["src_mac"]), header["vlan_id"],
                                     header["vlan_priority"], header["app_id"], header["reserved1"],
                                     header["reserved2"]), raw.hex()
        assert _native_pdu(native) == _python_pdu(pdu), raw.hex()
    return py_ok


@pytest.mark.parametrize("seed", range(20))
def test_pdu_parity(seed: int) -> None:
    rng = random.Random(seed)
    accepted = refused = 0
    for _ in range(150):
        apdu = _random_pdu(rng) if rng.random() < 0.5 else _odd_pdu(rng)
        _compare_pdu(apdu)
        for _ in range(10):
            if _compare_pdu(_mutate(rng, apdu)):
                accepted += 1
            else:
                refused += 1
    assert accepted > 50 and refused > 50  # the mutations exercise both outcomes


@pytest.mark.parametrize("seed", range(10))
def test_frame_parity(seed: int) -> None:
    rng = random.Random(1000 + seed)
    outcomes = set()
    for _ in range(150):
        vlan = rng.random() < 0.5
        raw = sv.encode_sv_frame(
            sv.SvPDU([_random_asdu(rng) for _ in range(rng.choice([1, 2]))]),
            dst_mac="01:0c:cd:04:00:01", src_mac="02:00:00:00:00:01", app_id=rng.randint(0, 0xFFFF),
            vlan_id=rng.randint(0, 0xFFF) if vlan else None, vlan_priority=rng.randint(0, 7) if vlan else None,
        ) + bytes(rng.choice([0, 0, 4, 30]))
        assert _compare_frame(raw)
        for _ in range(10):
            mutated = _mutate(rng, raw[:30]) + raw[30:] if rng.random() < 0.5 else _mutate(rng, raw)
            outcomes.add(_compare_frame(mutated))
    assert outcomes == {None, True, False}


def test_known_frame() -> None:
    sample = sv.encode_int32_samples([(-1000, 0), (2000, 0x2000)])
    raw = sv.encode_sv_frame(
        sv.SvPDU([sv.SvAsdu("IED01_MU01", n, 1, sv.SMP_SYNCH_GLOBAL, sample, smp_rate=4800) for n in (10, 11)]),
        dst_mac="01:0c:cd:04:00:01", src_mac="02:00:00:00:00:01", app_id=0x4000, vlan_id=5, vlan_priority=4,
    )
    header, (security, asdus) = rt.decode_sv_frame(raw)
    assert (header["app_id"], header["vlan_id"], header["vlan_priority"], security) == (0x4000, 5, 4, None)
    assert [(a["sv_id"], a["smp_cnt"], a["smp_synch"], a["smp_rate"], a["sample"]) for a in asdus] == [
        (b"IED01_MU01", 10, 2, 4800, sample), (b"IED01_MU01", 11, 2, 4800, sample)]
    assert rt.decode_sv_frame(raw[:12] + b"\x88\xb8" + raw[14:]) is None  # EtherType GOOSE: not SV
    with pytest.raises(ValueError, match="noASDU"):
        rt.decode_sv_pdu(ber.encode_tlv(0x60, ber.encode_tlv(0x80, b"\x02")))

# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for iec61850.ber."""

from __future__ import annotations

import pytest

from iec61850 import ber


@pytest.mark.parametrize(
    ("number", "cls", "constructed", "tag"),
    [
        (3, ber.CLASS_CONTEXT, False, 0x83),
        (2, ber.CLASS_CONTEXT, True, 0xA2),
        (1, ber.CLASS_APPLICATION, True, 0x61),
        (16, ber.CLASS_UNIVERSAL, True, 0x30),
        (30, ber.CLASS_CONTEXT, False, 0x9E),
        (31, ber.CLASS_CONTEXT, False, 0x9F1F),
        (72, ber.CLASS_CONTEXT, True, 0xBF48),
        (200, ber.CLASS_CONTEXT, False, 0x9F8148),
    ],
)
def test_tags(number: int, cls: int, constructed: bool, tag: int) -> None:
    assert ber.make_tag(number, cls, constructed) == tag
    assert ber.tag_number(tag) == number
    assert ber.is_constructed(tag) is constructed
    encoded = ber.encode_tag(tag)
    assert ber.decode_tag(encoded) == (tag, len(encoded))


@pytest.mark.parametrize(
    ("length", "encoded"),
    [(0, "00"), (127, "7f"), (128, "8180"), (255, "81ff"), (256, "820100"), (70000, "83011170")],
)
def test_lengths(length: int, encoded: str) -> None:
    assert ber.encode_length(length).hex() == encoded
    assert ber.decode_length(bytes.fromhex(encoded)) == (length, len(encoded) // 2)


def test_indefinite_length_is_rejected() -> None:
    with pytest.raises(ber.BerError):
        ber.decode_length(b"\x80")


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (0, "00"), (1, "01"), (127, "7f"), (128, "0080"), (256, "0100"),
        (-1, "ff"), (-128, "80"), (-129, "ff7f"), (-32768, "8000"), (2**31, "0080000000"),
    ],
)
def test_integers(value: int, encoded: str) -> None:
    assert ber.encode_integer(value).hex() == encoded
    assert ber.decode_integer(bytes.fromhex(encoded)) == value


def test_unsigned() -> None:
    assert ber.encode_unsigned(255).hex() == "00ff"
    assert ber.decode_unsigned(bytes.fromhex("00ff")) == 255
    assert ber.decode_unsigned(bytes.fromhex("ff")) == 255
    with pytest.raises(ValueError):
        ber.encode_unsigned(-1)


def test_tlv_round_trip_and_iteration() -> None:
    data = ber.encode_tlv(0x83, b"\xff") + ber.encode_tlv(0x89, bytes(200)) + ber.encode_tlv(0xBF48, b"")
    assert [(t.tag, len(t.value)) for t in ber.iter_tlvs(data)] == [(0x83, 1), (0x89, 200), (0xBF48, 0)]


def test_truncated_tlv() -> None:
    with pytest.raises(ber.BerError, match="truncated"):
        ber.decode_tlv(bytes.fromhex("8905aabb"))


def test_expect_tlv() -> None:
    with pytest.raises(ber.BerError, match="expected tag 0x61"):
        ber.expect_tlv(bytes.fromhex("6000"), 0, 0x61)


def test_boolean() -> None:
    assert ber.encode_boolean(True) == b"\xff"
    assert ber.decode_boolean(b"\x01") is True
    with pytest.raises(ber.BerError):
        ber.decode_boolean(b"")

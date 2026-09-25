# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for open61850.comtrade and Playback.from_comtrade.

The records are written here: two analog channels (IA in secondary values
with a 1000/1 ratio, VA in primary values) and two digital ones, 40
samples at 1 kHz, sample 6 of VA missing. The same files, read by the
``comtrade`` package from PyPI, gave the same values (within float32
rounding), digital states, times and trigger time.
"""

from __future__ import annotations

import math
import struct
from datetime import datetime

import pytest

from open61850.comtrade import ComtradeError, load_comtrade, parse_cfg, resample
from open61850.sv_publisher import Playback

N, RATE = 40, 1000.0
IA = [round(1000 * math.sin(2 * math.pi * 50 * n / RATE)) for n in range(N)]
VA = [round(20000 * math.cos(2 * math.pi * 50 * n / RATE)) for n in range(N)]
TRIP = [int(n >= 10) for n in range(N)]
CB = [int(n >= 25) for n in range(N)]


def _cfg(data_format: str, revision: str = "1999", nrates: str = "1", rate: str = f"{RATE:g},{N}") -> str:
    date = "09/25/2026" if revision == "1991" else "25/09/2026"
    head = "STATION01,REC01" + ("" if revision == "1991" else f",{revision}")
    lines = [head, "4,2A,2D",
             "1,IA,A,,A,0.01,0.5,0,-32767,32767,1000,1,S",
             "2,VA,A,,kV,0.002,0,0,-32767,32767,63.5,0.1,P"]
    lines += ["1,TRIP,0", "2,CB_OPEN,1"] if revision == "1991" else ["1,TRIP,,,0", "2,CB_OPEN,,,1"]
    lines += ["50", nrates, rate, f"{date},10:00:00.000000", f"{date},10:00:00.010000", data_format, "1"]
    return "\r\n".join(lines) + "\r\n"


def _write(tmp_path, data_format: str, **cfg_options) -> str:
    cfg = tmp_path / f"{data_format}.cfg"
    cfg.write_text(_cfg(data_format, **cfg_options), newline="")
    if data_format == "ASCII":
        rows = [f"{n + 1},{n * 1000},{IA[n]},{99999 if n == 5 else VA[n]},{TRIP[n]},{CB[n]}" for n in range(N)]
        (tmp_path / "ASCII.dat").write_text("\r\n".join(rows) + "\r\n", newline="")
    else:
        code = {"BINARY": "h", "BINARY32": "i", "FLOAT32": "f"}[data_format]
        missing = {"BINARY": -0x8000, "BINARY32": -0x80000000, "FLOAT32": math.nan}[data_format]
        data = b"".join(struct.pack(f"<II2{code}H", n + 1, n * 1000, IA[n], missing if n == 5 else VA[n],
                                    TRIP[n] | CB[n] << 1) for n in range(N))
        (tmp_path / f"{data_format}.dat").write_bytes(data)
    return str(cfg)


@pytest.mark.parametrize("data_format", ["ASCII", "BINARY", "BINARY32", "FLOAT32"])
def test_formats(tmp_path, data_format: str) -> None:
    record = load_comtrade(_write(tmp_path, data_format))
    assert (record.station, record.device, record.revision, record.frequency) == ("STATION01", "REC01", "1999", 50)
    assert [c.ch_id for c in record.analog_channels] == ["IA", "VA"]
    assert record.start == datetime(2026, 9, 25, 10) and record.trigger == datetime(2026, 9, 25, 10, 0, 0, 10000)
    # IA is recorded in secondary values: primary = (0.01 * raw + 0.5) * 1000 / 1
    assert record.analog("IA")[3] == pytest.approx((0.01 * IA[3] + 0.5) * 1000)
    assert record.analog(0, primary=False)[3] == pytest.approx(0.01 * IA[3] + 0.5)
    # VA is in primary values: secondary = value * 0.1 / 63.5
    assert record.analog(1)[0] == pytest.approx(0.002 * VA[0])
    assert record.analog(1, primary=False)[0] == pytest.approx(0.002 * VA[0] * 0.1 / 63.5)
    assert math.isnan(record.analog(1)[5])
    assert record.digital(0) == TRIP and record.digital("CB_OPEN") == CB
    times = record.times()
    assert len(times) == N and times[1] == pytest.approx(0.001) and times[-1] == pytest.approx(0.039)


def test_timestamps_when_no_rate(tmp_path) -> None:
    record = load_comtrade(_write(tmp_path, "ASCII", nrates="0", rate="0,40"))
    assert record.rates == []
    assert record.times()[2] == pytest.approx(0.002)  # timestamps in microseconds, timemult 1


def test_revision_1991(tmp_path) -> None:
    record = load_comtrade(_write(tmp_path, "BINARY", revision="1991"))
    assert record.revision == "1991" and record.start == datetime(2026, 9, 25, 10)
    assert [c.normal for c in record.digital_channels] == [0, 1]


def test_bad_files(tmp_path) -> None:
    with pytest.raises(ComtradeError, match="channels announced"):
        parse_cfg("S,R,1999\n3,2A,2D\n")
    with pytest.raises(ComtradeError, match="data format"):
        parse_cfg(_cfg("HEX"))
    cfg = _write(tmp_path, "BINARY")
    (tmp_path / "BINARY.dat").write_bytes(b"\x00" * 13)
    with pytest.raises(ComtradeError, match="whole number"):
        load_comtrade(cfg)


def test_resample() -> None:
    assert resample([0.0, 1.0], [0.0, 10.0], 4) == [0.0, 2.5, 5.0, 7.5, 10.0]
    assert resample([0.0, 0.5, 1.0], [1.0, math.nan, 3.0], 2) == [1.0, 0.0, 3.0]
    assert resample([], [], 10) == []


def test_playback_from_comtrade(tmp_path) -> None:
    record = load_comtrade(_write(tmp_path, "FLOAT32"))
    playback = Playback.from_comtrade(record, ["IA", None, 1], rate=4000, scales=[1000, 1, 100], start_second=5)
    assert playback.channels == 3 and len(playback.values) == 157  # 39 ms at 4 kHz, both ends included
    first, second = playback.values[0], playback.values[4]  # 4 samples at 4 kHz = the record's second sample
    assert first == (round((0.01 * IA[0] + 0.5) * 1000 * 1000), 0, round(0.002 * VA[0] * 100))
    assert second[0] == round((0.01 * IA[1] + 0.5) * 1000 * 1000)
    assert playback.values[20][2] == 0  # VA missing at 5 ms counts as 0
    assert playback.values[22][2] == round(0.002 * VA[6] * 100 / 2)  # halfway to the next sample
    with pytest.raises(ValueError):
        Playback.from_comtrade(record, ["IA"], rate=4000, scales=[1, 2])

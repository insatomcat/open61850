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

import json
import math
import shutil
import struct
import subprocess
import zipfile
from datetime import datetime

import pytest

from open61850.comtrade import (
    AnalogChannel,
    Comtrade,
    ComtradeError,
    DigitalChannel,
    load_comtrade,
    parse_cfg,
    resample,
    save_comtrade,
    viewer_script,
)
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


def _record(data_format: str, revision: str) -> Comtrade:
    ia = [float(v) for v in IA]
    va: list = [float(v) for v in VA]
    va[5] = None
    return Comtrade(
        "STATION01", "REC01", revision,
        [AnalogChannel(1, "IA", "A", "", "A", 0.01, 0.5, 0.0, -32767, 32767, 1000.0, 1.0, "S"),
         AnalogChannel(2, "VA", "A", "", "kV", 0.002, 0.0, 0.0, -32767, 32767, 63.5, 0.1, "P")],
        [DigitalChannel(1, "TRIP", "", "", 0), DigitalChannel(2, "CB_OPEN", "", "", 1)],
        50.0, [(RATE, N)], datetime(2026, 9, 25, 10), datetime(2026, 9, 25, 10, 0, 0, 10000), data_format,
        numbers=list(range(1, N + 1)), timestamps=[n * 1000 for n in range(N)],
        raw_analog=[ia, va], raw_digital=[list(TRIP), list(CB)],
    )


@pytest.mark.parametrize("revision", ["1999", "2013"])
@pytest.mark.parametrize("data_format", ["ASCII", "BINARY", "BINARY32", "FLOAT32"])
def test_save_reads_back(tmp_path, data_format: str, revision: str) -> None:
    record = _record(data_format, revision)
    record.tmq_code, record.leap_second = ("0", 0) if revision == "2013" else (None, None)
    save_comtrade(record, tmp_path / "rec.cfg")
    back = load_comtrade(tmp_path / "rec.cfg")
    assert (back.station, back.device, back.revision, back.data_format) == ("STATION01", "REC01", revision, data_format)
    assert back.analog_channels == record.analog_channels and back.digital_channels == record.digital_channels
    assert (back.frequency, back.rates, back.start, back.trigger) == (50.0, [(RATE, N)], record.start, record.trigger)
    assert back.numbers == record.numbers and back.timestamps == record.timestamps
    assert back.raw_analog == record.raw_analog and back.raw_digital == record.raw_digital
    assert back.analog("IA")[3] == pytest.approx((0.01 * IA[3] + 0.5) * 1000) and math.isnan(back.analog("VA")[5])
    if revision == "2013":
        assert (back.time_code, back.local_code, back.tmq_code, back.leap_second) == ("0", "0", "0", 0)
    else:
        assert back.time_code is None and back.tmq_code is None
    assert not list(tmp_path.glob(".*"))  # no temporary file left


def test_save_refuses(tmp_path) -> None:
    record = _record("BINARY", "1999")
    record.raw_analog[0][0] = 40000.0  # beyond 16 bits
    with pytest.raises(ComtradeError, match="does not fit"):
        save_comtrade(record, tmp_path / "rec.cfg")
    record = _record("BINARY32", "1991")
    with pytest.raises(ComtradeError, match="revision"):
        save_comtrade(record, tmp_path / "rec.cfg")
    record = _record("BINARY32", "2013")
    record.raw_digital[1].pop()
    with pytest.raises(ComtradeError, match="samples"):
        save_comtrade(record, tmp_path / "rec.cfg")
    assert not list(tmp_path.iterdir())


def test_save_many_digital_channels(tmp_path) -> None:
    record = _record("BINARY32", "2013")
    record.digital_channels = [DigitalChannel(k + 1, f"D{k}", "", "", 0) for k in range(20)]
    record.raw_digital = [[(n >> (k % 6)) & 1 for n in range(N)] for k in range(20)]  # two 16-bit words
    record.timestamps = [None] * N  # the rate gives the times
    save_comtrade(record, tmp_path / "rec.cfg")
    back = load_comtrade(tmp_path / "rec.cfg")
    assert back.raw_digital == record.raw_digital and back.timestamps == [None] * N
    assert back.times()[1] == pytest.approx(0.001)


_NODE = shutil.which("node")
_READ = """
const fs = require("fs");
const [cfg, dat, zip] = process.argv.slice(2);
const read = path => { const b = fs.readFileSync(path); return b.buffer.slice(b.byteOffset, b.byteOffset + b.length); };
const out = r => ({count: r.count, time: [...r.time], values: r.values.map(v => [...v].map(x => Number.isNaN(x) ? null : x)),
                   bits: r.bits.map(b => [...b]), ids: r.analog.map(c => c.id), ccbm: r.analog.map(c => c.ccbm)});
(async () => {
  const flat = ComtradeViewer.parse(fs.readFileSync(cfg, "latin1"), read(dat));
  console.log(JSON.stringify([out(flat), out(await ComtradeViewer.fromZip(read(zip)))]));
})();
"""


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
@pytest.mark.parametrize(("data_format", "revision"), [("ASCII", "1999"), ("BINARY", "1991"), ("BINARY32", "2013"),
                                                       ("FLOAT32", "1999")])
def test_the_viewer_reads_as_this_module(tmp_path, data_format: str, revision: str) -> None:
    """The page's viewer, run by node, reads a record as load_comtrade does: each analog value (a x + b, a missing
    one missing), each digital state, each time from the trigger; from its files and from a zip of them."""
    cfg = _write(tmp_path, data_format, revision=revision)
    dat = cfg.removesuffix(".cfg") + ".dat"
    with zipfile.ZipFile(tmp_path / "rec.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in (cfg, dat):
            archive.write(path, path.rsplit("/", 1)[-1])
    script = tmp_path / "read.js"
    script.write_text(viewer_script() + _READ, encoding="utf-8")
    flat, zipped = json.loads(subprocess.run([_NODE, str(script), cfg, dat, str(tmp_path / "rec.zip")], check=True,
                                             capture_output=True, text=True).stdout)
    record = load_comtrade(cfg)
    assert flat == zipped and flat["count"] == N and flat["ids"] == ["IA", "VA"] and flat["ccbm"] == ["", ""]
    for k, channel in enumerate(record.analog_channels):
        expected = [None if v is None or math.isnan(v) else channel.a * v + channel.b for v in record.raw_analog[k]]
        # pytest 9.2 refuses None in approx with rel: missing values are compared by position, the others approx.
        assert [i for i, v in enumerate(flat["values"][k]) if v is None] == [i for i, v in enumerate(expected) if v is None]
        assert [v for v in flat["values"][k] if v is not None] == pytest.approx([v for v in expected if v is not None],
                                                                                 rel=1e-6)
    assert flat["bits"] == record.raw_digital
    trigger = (record.trigger - record.start).total_seconds()
    assert flat["time"] == pytest.approx([t - trigger for t in record.times()], abs=1e-9)


def test_the_viewer_is_shipped() -> None:
    script = viewer_script()
    assert script.startswith("// Copyright") and "const ComtradeViewer" in script and "\u2014" not in script


_FRAME = """
const line = [1.888, 4.803], reach = 2.5 * Math.hypot(...line);
const base = [[0, 0], line, [-reach * 0.6, -reach * 0.6], [reach, reach]];
const frame = loops => { const f = ComtradeViewer.rxFrame(base, loops); return [f.r0, f.r0 + f.span, f.x1 - f.span, f.x1]; };
console.log(JSON.stringify({line: frame([]), fault: frame([[25.75, 1.92]]), load: frame([[92, 30]]),
                            arrow: ComtradeViewer.edgeArrow(900, 170, 340), up: ComtradeViewer.edgeArrow(170, -50, 340)}));
"""


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_the_rx_view_takes_a_fault_in_and_leaves_a_load_out(tmp_path) -> None:
    """The R-X view holds the line and its reach, and a fault's loop past it (a three phase fault through 25 ohms on
    a line of 5.16 ohms, on its own feeder without a relay's zones: it was drawn out of the view); a load's, farther,
    is left out, and an arrow on the view's edge points to a loop out of it."""
    script = tmp_path / "frame.js"
    script.write_text(viewer_script() + _FRAME, encoding="utf-8")
    seen = json.loads(subprocess.run([_NODE, str(script)], check=True, capture_output=True, text=True).stdout)
    r0, r1, x0, x1 = seen["fault"]
    assert r0 < 0 and r1 > 25.75 and x0 < 1.92 < x1
    assert seen["load"] == seen["line"] and seen["line"][1] < 25.75
    assert seen["arrow"] == [336, 170, 0] and seen["up"] == [170, 4, -90]

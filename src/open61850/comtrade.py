# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""COMTRADE records (IEEE C37.111 / IEC 60255-24), read with no dependency.

A record is a ``.cfg`` file (channels, rates, times, data format) and a
``.dat`` file (the samples), in ASCII, BINARY (16 bits), BINARY32 or
FLOAT32; revisions 1991, 1999 and 2013 (``.cff`` single files are not
read). :func:`load_comtrade` returns a :class:`Comtrade` whose analog
channels come out in primary or secondary values, with the time of every
sample. :func:`resample` puts a channel on a regular grid, which is how a
fault record becomes Sampled Values (:meth:`open61850.sv_publisher.Playback.from_comtrade`)::

    record = load_comtrade("fault.cfg")
    print(record.analog_channels[0].ch_id, record.analog(0)[:5])
"""

from __future__ import annotations

import bisect
import math
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

__all__ = [
    "AnalogChannel",
    "DigitalChannel",
    "Comtrade",
    "ComtradeError",
    "load_comtrade",
    "parse_cfg",
    "resample",
]


class ComtradeError(ValueError):
    """The files do not follow C37.111."""


@dataclass
class AnalogChannel:
    index: int  # An, from 1
    ch_id: str
    phase: str
    ccbm: str
    unit: str
    a: float  # value = a * raw + b, in the file's primary or secondary values (ps)
    b: float
    skew_us: float
    min: float
    max: float
    primary: float = 1.0
    secondary: float = 1.0
    ps: str = "P"


@dataclass
class DigitalChannel:
    index: int
    ch_id: str
    phase: str
    ccbm: str
    normal: int


@dataclass
class Comtrade:
    station: str
    device: str
    revision: str
    analog_channels: list[AnalogChannel]
    digital_channels: list[DigitalChannel]
    frequency: float
    rates: list[tuple[float, int]]  # (samples per second, last sample number)
    start: Optional[datetime]
    trigger: Optional[datetime]
    data_format: str
    timemult: float = 1.0
    numbers: list[int] = field(default_factory=list)
    timestamps: list[Optional[int]] = field(default_factory=list)  # in microseconds times timemult
    raw_analog: list[list[Optional[float]]] = field(default_factory=list)  # per channel, None = missing
    raw_digital: list[list[int]] = field(default_factory=list)

    def _channel(self, ref: Union[int, str]) -> int:
        if isinstance(ref, int):
            if not 0 <= ref < len(self.analog_channels):
                raise IndexError(f"no analog channel {ref}")
            return ref
        for i, channel in enumerate(self.analog_channels):
            if channel.ch_id == ref:
                return i
        raise KeyError(f"no analog channel {ref!r}")

    def analog(self, ref: Union[int, str], primary: bool = True) -> list[float]:
        """Values of an analog channel (index from 0, or ch_id); missing samples are NaN."""
        i = self._channel(ref)
        channel = self.analog_channels[i]
        factor = 1.0
        if primary and channel.ps.upper() == "S" and channel.secondary:
            factor = channel.primary / channel.secondary
        elif not primary and channel.ps.upper() == "P" and channel.primary:
            factor = channel.secondary / channel.primary
        return [math.nan if raw is None else (channel.a * raw + channel.b) * factor for raw in self.raw_analog[i]]

    def digital(self, ref: Union[int, str]) -> list[int]:
        if isinstance(ref, str):
            ref = next((i for i, c in enumerate(self.digital_channels) if c.ch_id == ref), -1)
            if ref < 0:
                raise KeyError("no such digital channel")
        return self.raw_digital[ref]

    def times(self) -> list[float]:
        """Time of each sample in seconds from the first one: from the rates, else from the timestamps."""
        count = len(self.numbers)
        if self.rates and all(rate > 0 for rate, _ in self.rates):
            out, t, n = [], 0.0, 1
            for rate, last in self.rates:
                while n <= min(last, count):
                    out.append(t)
                    t += 1.0 / rate
                    n += 1
            while len(out) < count:  # samples past the last endsamp keep the last rate
                out.append(t)
                t += 1.0 / self.rates[-1][0]
            return out
        if any(ts is None for ts in self.timestamps):
            raise ComtradeError("no sample rate and missing timestamps")
        first = self.timestamps[0] or 0
        return [((ts or 0) - first) * self.timemult * 1e-6 for ts in self.timestamps]


def _fields(line: str) -> list[str]:
    return [f.strip() for f in line.split(",")]


def _float(text: str, default: float = 0.0) -> float:
    return float(text) if text.strip() else default


def _datetime(text: str, revision: str) -> Optional[datetime]:
    date, _, clock = text.partition(",")
    date, clock = date.strip(), clock.strip()
    if not date or not clock:
        return None
    first, second, year = (int(x) for x in date.split("/"))
    day, month = (second, first) if revision == "1991" else (first, second)
    if year < 100:
        year += 1900 if year >= 70 else 2000
    hms, _, frac = clock.partition(".")
    hour, minute, sec = (int(x) for x in hms.split(":"))
    micro = int((frac + "000000")[:6]) if frac else 0
    return datetime(year, month, day, hour, minute, sec, micro)


def parse_cfg(text: str) -> Comtrade:
    """A record's configuration (no samples yet)."""
    lines = [line.rstrip("\r") for line in text.splitlines()]
    try:
        head = _fields(lines[0])
        revision = head[2] if len(head) > 2 and head[2] else "1991"
        counts = _fields(lines[1])
        total = int(counts[0])
        n_analog = int(counts[1].rstrip("Aa"))
        n_digital = int(counts[2].rstrip("Dd"))
        if n_analog + n_digital != total:
            raise ComtradeError(f"{total} channels announced, {n_analog}A + {n_digital}D given")
        pos = 2
        analog = []
        for _ in range(n_analog):
            f = _fields(lines[pos]) + [""] * 13
            analog.append(AnalogChannel(
                int(f[0]), f[1], f[2], f[3], f[4], _float(f[5], 1.0), _float(f[6]), _float(f[7]),
                _float(f[8]), _float(f[9]), _float(f[10], 1.0), _float(f[11], 1.0), f[12] or "P",
            ))
            pos += 1
        digital = []
        for _ in range(n_digital):
            f = _fields(lines[pos]) + [""] * 5
            if revision == "1991":  # Dn,ch_id,y
                digital.append(DigitalChannel(int(f[0]), f[1], "", "", int(f[2] or 0)))
            else:
                digital.append(DigitalChannel(int(f[0]), f[1], f[2], f[3], int(f[4] or 0)))
            pos += 1
        frequency = _float(lines[pos])
        nrates = int(lines[pos + 1].strip())
        pos += 2
        rates = []
        for _ in range(max(nrates, 1)):  # nrates 0 still has a "0,endsamp" line
            f = _fields(lines[pos])
            rates.append((_float(f[0]), int(f[1])))
            pos += 1
        start = _datetime(lines[pos], revision)
        trigger = _datetime(lines[pos + 1], revision)
        data_format = lines[pos + 2].strip().upper() if pos + 2 < len(lines) else "ASCII"
        timemult = _float(lines[pos + 3], 1.0) if pos + 3 < len(lines) and lines[pos + 3].strip() else 1.0
    except (IndexError, ValueError) as exc:
        if isinstance(exc, ComtradeError):
            raise
        raise ComtradeError(f"bad .cfg: {exc}") from exc
    if data_format not in ("ASCII", "BINARY", "BINARY32", "FLOAT32"):
        raise ComtradeError(f"unknown data format {data_format!r}")
    if nrates == 0:
        rates = []
    return Comtrade(head[0], head[1] if len(head) > 1 else "", revision, analog, digital, frequency, rates,
                    start, trigger, data_format, timemult)


def _read_ascii(record: Comtrade, data: bytes) -> None:
    n_a, n_d = len(record.analog_channels), len(record.digital_channels)
    for line in data.decode("latin-1").splitlines():
        if not line.strip() or line.strip() == "\x1a":
            continue
        f = _fields(line)
        if len(f) < 2 + n_a + n_d:
            raise ComtradeError(f"sample line with {len(f)} fields, {2 + n_a + n_d} expected")
        record.numbers.append(int(f[0]))
        record.timestamps.append(int(f[1]) if f[1] else None)
        for i in range(n_a):
            text = f[2 + i]
            value = float(text) if text else None
            record.raw_analog[i].append(None if value is None or value == 99999 else value)
        for i in range(n_d):
            record.raw_digital[i].append(int(f[2 + n_a + i]))


_BINARY = {"BINARY": ("h", -0x8000), "BINARY32": ("i", -0x80000000), "FLOAT32": ("f", None)}


def _read_binary(record: Comtrade, data: bytes) -> None:
    code, missing = _BINARY[record.data_format]
    n_a, n_d = len(record.analog_channels), len(record.digital_channels)
    words = (n_d + 15) // 16
    row = struct.Struct(f"<II{n_a}{code}{words}H")
    if len(data) % row.size:
        raise ComtradeError(f".dat of {len(data)} bytes is not a whole number of {row.size}-byte samples")
    for values in row.iter_unpack(data):
        record.numbers.append(values[0])
        record.timestamps.append(None if values[1] == 0xFFFFFFFF else values[1])
        for i in range(n_a):
            raw = values[2 + i]
            record.raw_analog[i].append(None if raw == missing or (missing is None and math.isnan(raw)) else raw)
        for i in range(n_d):
            record.raw_digital[i].append((values[2 + n_a + i // 16] >> (i % 16)) & 1)


def load_comtrade(cfg: Union[str, Path], dat: Union[str, Path, None] = None) -> Comtrade:
    """Read ``cfg`` and its data file (``dat``, by default the ``.cfg`` with a ``.dat`` suffix, any case)."""
    cfg_path = Path(cfg)
    record = parse_cfg(cfg_path.read_bytes().decode("latin-1"))
    if dat is None:
        candidates = [cfg_path.with_suffix(s) for s in (".dat", ".DAT", ".Dat")]
        dat = next((c for c in candidates if c.exists()), candidates[0])
    data = Path(dat).read_bytes()
    record.raw_analog = [[] for _ in record.analog_channels]
    record.raw_digital = [[] for _ in record.digital_channels]
    if record.data_format == "ASCII":
        _read_ascii(record, data)
    else:
        _read_binary(record, data)
    return record


def resample(times: list[float], values: list[float], rate: int) -> list[float]:
    """``values`` taken at ``times`` (seconds, increasing), linearly interpolated every ``1 / rate`` s.

    The grid starts at ``times[0]`` and stops at the last time; a missing
    value (NaN) counts as 0.
    """
    if len(times) != len(values):
        raise ValueError("times and values differ in length")
    if not times:
        return []
    clean = [0.0 if math.isnan(v) else v for v in values]
    t0, span = times[0], times[-1] - times[0]
    out = []
    for k in range(int(math.floor(span * rate + 1e-9)) + 1):
        t = t0 + k / rate
        j = bisect.bisect_right(times, t) - 1
        if j >= len(times) - 1:
            out.append(clean[-1])
            continue
        t_a, t_b = times[j], times[j + 1]
        weight = 0.0 if t_b == t_a else (t - t_a) / (t_b - t_a)
        out.append(clean[j] + (clean[j + 1] - clean[j]) * weight)
    return out

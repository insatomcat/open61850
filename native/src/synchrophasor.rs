// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! A PMU's work per report, for a subscriber of `open61850.sv_receiver`:
//! the records of one SV stream placed in time, the synchrophasors of
//! IEC/IEEE 60255-118-1's Annex D (classes P and M), and each report as an
//! IEEE C37.118.2 data frame.
//!
//! It is vpac-wams' Python PMU (`vpac_wams.pmu`, `vpac_wams.synchrophasor`)
//! written again step for step, that PMU staying the reference its tests
//! compare this with: the filter is designed there and given here as taps.
//! In Python a report took about 100 us, most of it in the interpreter
//! (vpac-wams' HISTORY.md, W2h).
//!
//! - **Placing a sample.** A record's second is its capture time minus
//!   `smpCnt / fs`, rounded; its global index `second * fs + smpCnt`. A
//!   gap is kept as NaN, or filled by a straight line when it holds at most
//!   `fill` samples and the sample before it is whole (the reports whose
//!   window holds a filled sample are "data modified"). A sample older than
//!   the last one taken is dropped and counted late, and the last one taken
//!   becomes NaN: a merging unit's time stepping back leaves no window
//!   spanning it unflagged. A silence longer than half the buffer starts
//!   again.
//! - **The time check.** Capture time minus label time, the least over the
//!   last 0.25 s, is the merging unit's error (transit included); the time
//!   is synchronised while smpSynch is 2 (global) and the error within the
//!   tolerance. It gives STAT's bits 13, 8-6 and 5-4 and the frame's time
//!   quality.
//! - **The estimator.** The samples demodulated by a cosine at `f0` peaking
//!   on every UNIX second and filtered by the taps around the reporting
//!   instant; the positive sequence; frequency and ROCOF from its angle's
//!   first and second differences over `span` samples each side; class P's
//!   magnitude correction.
//! - **The frame.** One PMU, phasors in polar float, frequency and ROCOF
//!   float, no analog or digital: STAT, the voltages (A, B, C, positive),
//!   then the currents when the unit has them (NaN when no current report
//!   matches), CRC-CCITT.

use std::collections::VecDeque;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

const NS: i64 = 1_000_000_000;
const HEADER: usize = 16;
const FLAG_SIMULATION: u8 = 1;
const FLAG_CHANNELS: u8 = 2;
const QUALITY_MISSING: u32 = 1;
const TWO_PI: f64 = 2.0 * std::f64::consts::PI;
const WINDOW_NS: i64 = 250_000_000;

const STAT_MODIFIED: u16 = 1 << 9;
const STAT_TEST: u16 = 0b10 << 14;
const STAT_INVALID: u16 = 0b11 << 14;
const STAT_NOT_SYNC: u16 = 1 << 13;
const STAT_TIME_UNKNOWN: u16 = 0b111 << 6;

extern "C" {
    fn remainder(x: f64, y: f64) -> f64;
}

fn ieee_remainder(x: f64) -> f64 {
    // SAFETY: libm's remainder, a pure function of two doubles (Python's math.remainder)
    unsafe { remainder(x, TWO_PI) }
}

#[derive(Clone, Copy)]
struct C {
    re: f64,
    im: f64,
}

impl C {
    fn add(self, o: C) -> C {
        C { re: self.re + o.re, im: self.im + o.im }
    }
    fn mul(self, o: C) -> C {
        C { re: self.re * o.re - self.im * o.im, im: self.re * o.im + self.im * o.re }
    }
    fn scale(self, k: f64) -> C {
        C { re: self.re * k, im: self.im * k }
    }
    fn div(self, k: f64) -> C {
        C { re: self.re / k, im: self.im / k }
    }
    fn abs(self) -> f64 {
        self.re.hypot(self.im)
    }
    fn arg(self) -> f64 {
        self.im.atan2(self.re)
    }
    fn nan() -> C {
        C { re: f64::NAN, im: f64::NAN }
    }
}

#[derive(Default, Clone, Copy)]
struct Counters {
    samples: u64,
    missing: u64,
    late: u64,
    filled: u64,
    reports: u64,
    invalid_reports: u64,
}

struct Measurement {
    phases: [C; 3],
    positive: C,
    frequency: f64,
    rocof: f64,
}

/// The estimator: the taps (normalised, with sqrt 2), the reference's values over a cycle.
struct Estimator {
    fs: i64,
    f0: f64,
    taps: Vec<f64>,
    half: i64,
    span: i64,
    class_p: bool,
    reference: Vec<C>,
    a: C,
    a2: C,
}

impl Estimator {
    fn reach(&self) -> i64 {
        self.half + self.span
    }

    fn phasors(&self, g: &Group, centre: i64) -> [C; 3] {
        let pc = self.reference.len() as i64;
        let mut acc = [C { re: 0.0, im: 0.0 }; 3];
        let first = centre - self.half;
        for (k, w) in self.taps.iter().enumerate() {
            let idx = first + k as i64;
            let r = self.reference[idx.rem_euclid(pc) as usize].scale(*w);
            let x = &g.buf[(idx - g.base) as usize];
            for ch in 0..3 {
                acc[ch] = acc[ch].add(r.scale(x[ch]));
            }
        }
        acc
    }

    fn report(&self, g: &Group, centre: i64) -> Measurement {
        let s = self.span;
        let ph = [self.phasors(g, centre - s), self.phasors(g, centre), self.phasors(g, centre + s)];
        let pos: Vec<C> = ph.iter().map(|p| p[0].add(self.a.mul(p[1])).add(self.a2.mul(p[2])).div(3.0)).collect();
        let th: Vec<f64> = pos.iter().map(|p| p.arg()).collect();
        let d1 = ieee_remainder(th[2] - th[0]);
        let d2 = ieee_remainder(th[2] - th[1]) - ieee_remainder(th[1] - th[0]);
        let dt = s as f64 / self.fs as f64;
        let df = d1 / (2.0 * dt) / TWO_PI;
        let rocof = d2 / (dt * dt) / TWO_PI;
        let mut phases = ph[1];
        let mut positive = pos[1];
        if self.class_p {
            let gain = 1.0 / (std::f64::consts::PI * (self.f0 + 1.625 * df) / (2.0 * self.f0)).sin();
            for p in phases.iter_mut() {
                *p = p.scale(gain);
            }
            positive = positive.scale(gain);
        }
        Measurement { phases, positive, frequency: self.f0 + df, rocof }
    }
}

/// Three channels of one stream (the voltages, or the currents), placed on the global sample index.
struct Group {
    cols: [usize; 3],
    lsb: f64,
    buf: Vec<[f64; 3]>,
    cap: i64,
    started: bool,
    base: i64,
    next: i64,
    centre: i64,
    step: i64,
    keep: i64,
    reach: i64,
    fill: i64,
    marked: Option<i64>,
    filled: VecDeque<(i64, i64)>,
    counters: Counters,
}

impl Group {
    fn first_centre(&self, index: i64) -> i64 {
        // ceil((index + reach) / step) * step, as Python's -(-a // b) * b
        -((-(index + self.reach)).div_euclid(self.step)) * self.step
    }

    fn add(&mut self, index: i64, values: [f64; 3]) {
        if !self.started {
            self.started = true;
            self.base = index;
            self.next = index;
            self.centre = self.first_centre(index);
        }
        if index < self.next {
            self.counters.late += 1;
            if self.marked != Some(self.next) && self.next > self.base {
                self.buf[(self.next - 1 - self.base) as usize] = [f64::NAN; 3];
                self.marked = Some(self.next);
            }
            return;
        }
        if index - self.next > self.cap / 2 {
            self.base = index;
            self.next = index;
            self.buf.fill([f64::NAN; 3]);
            self.centre = self.first_centre(index);
        }
        let mut pos = index - self.base;
        if pos >= self.cap {
            let src = (self.next - self.base - self.keep).max(0);
            let n = self.next - self.base - src;
            // Only the samples a pending report needs move; what lies past them is written before it is read
            // (a sample, or a gap made NaN or filled). Making it NaN as well cost 460 kB a group, at the same
            // wake for every stream of one clock: 7 ms every 4 s with 64 streams on a Xeon Silver 4310.
            self.buf.copy_within(src as usize..(src + n) as usize, 0);
            self.base += src;
            pos = index - self.base;
        }
        let gap = index - self.next;
        if gap > 0 {
            self.counters.missing += gap as u64;
            let prev = pos - gap - 1;
            if gap <= self.fill && prev >= 0 && !self.buf[prev as usize].iter().any(|v| v.is_nan()) {
                let p = self.buf[prev as usize];
                for j in 1..=gap {
                    let w = j as f64 / (gap + 1) as f64;
                    let mut row = [0.0; 3];
                    for ch in 0..3 {
                        row[ch] = p[ch] + w * (values[ch] - p[ch]);
                    }
                    self.buf[(prev + j) as usize] = row;
                }
                self.filled.push_back((self.next, index));
                self.counters.filled += gap as u64;
            } else {
                self.buf[(self.next - self.base) as usize..pos as usize].fill([f64::NAN; 3]);
            }
        }
        self.buf[pos as usize] = values;
        self.next = index + 1;
        self.counters.samples += 1;
    }

    fn need(&self) -> i64 {
        if !self.started {
            return 1;
        }
        (self.centre + self.reach + 1 - self.next).max(1)
    }

    /// The reports whose samples are all in: (instant, measurement, window holds filled samples).
    fn ready(&mut self, est: &Estimator) -> Vec<(i64, Measurement, bool)> {
        let mut out = Vec::new();
        while self.started && self.next > self.centre + self.reach {
            let c = self.centre;
            self.centre += self.step;
            if c - self.reach < self.base {
                continue;
            }
            let (lo, hi) = (c - self.reach, c + self.reach + 1);
            while matches!(self.filled.front(), Some(&(_, b)) if b <= lo) {
                self.filled.pop_front();
            }
            let modified = self.filled.iter().any(|&(a, b)| a < hi && b > lo);
            out.push((c, est.report(self, c), modified));
        }
        out
    }
}

struct TimeCheck {
    tolerance_ns: i64,
    error_ns: Option<i64>,
    synch: u8,
    lost_ns: Option<i64>,
    now_ns: i64,
    last_ts: Option<i64>,
    mins: VecDeque<(i64, i64)>,
}

impl TimeCheck {
    fn synchronised(&self) -> bool {
        self.synch == 2 && matches!(self.error_ns, Some(e) if e.abs() <= self.tolerance_ns)
    }

    fn update(&mut self, ts: &[i64], label: &[i64], synch: u8) {
        let mut least: Option<i64> = None;
        let mut prev = self.last_ts;
        for (t, l) in ts.iter().zip(label) {
            if Some(*t) != prev {
                let d = t - l;
                least = Some(least.map_or(d, |m: i64| m.min(d)));
            }
            prev = Some(*t);
        }
        let now = *ts.last().expect("records");
        self.last_ts = Some(now);
        self.now_ns = now;
        if let Some(m) = least {
            self.mins.push_back((now, m));
        }
        while matches!(self.mins.front(), Some(&(t, _)) if t < now - WINDOW_NS) {
            self.mins.pop_front();
        }
        if let Some(m) = self.mins.iter().map(|&(_, m)| m).min() {
            self.error_ns = Some(-m);
        }
        self.synch = synch;
        if self.synchronised() {
            self.lost_ns = None;
        } else if self.lost_ns.is_none() {
            self.lost_ns = Some(now);
        }
    }

    fn stat(&self) -> u16 {
        if self.synchronised() {
            return 0b010 << 6;
        }
        let mut s = STAT_NOT_SYNC;
        match self.error_ns {
            None => s |= STAT_TIME_UNKNOWN,
            Some(e) => {
                let err = e.abs() as f64 / NS as f64;
                let bounds = [(100e-9, 0b001), (1e-6, 0b010), (10e-6, 0b011), (100e-6, 0b100), (1e-3, 0b101), (10e-3, 0b110)];
                let code = bounds.iter().find(|(b, _)| err < *b).map_or(0b111, |&(_, c)| c);
                s |= code << 6;
            }
        }
        let lost = self.lost_ns.map_or(0.0, |l| (self.now_ns - l) as f64 / NS as f64);
        let unlocked = if lost < 10.0 { 0 } else if lost < 100.0 { 1 } else if lost < 1000.0 { 2 } else { 3 };
        s | unlocked << 4
    }

    fn message_quality(&self) -> u8 {
        if self.synchronised() {
            return 0;
        }
        match self.error_ns {
            None => 0x0F,
            Some(e) => {
                let err = e.abs().max(1) as f64;
                let k = 1.max(err.log10().ceil() as i64 + 1);
                if k <= 0x0B {
                    k as u8
                } else {
                    0x0F
                }
            }
        }
    }
}

fn crc(data: &[u8]) -> u16 {
    let mut c: u16 = 0xFFFF;
    for &b in data {
        c ^= (b as u16) << 8;
        for _ in 0..8 {
            c = if c & 0x8000 != 0 { (c << 1) ^ 0x1021 } else { c << 1 };
        }
    }
    c
}

/// One PMU: a stream's voltages and optionally its currents, the time check, its data frames.
#[pyclass(module = "open61850_rt")]
pub struct PhasorUnit {
    est: Estimator,
    groups: Vec<Group>,
    time: TimeCheck,
    channels: usize,
    idcode: u16,
    time_base: i64,
    head: [u8; 2],
    test_mode: bool,
    smp_synch: u8,
    simulation: bool,
    frames: u64,
}

#[pymethods]
impl PhasorUnit {
    /// `taps`: the filter (normalised, sqrt 2 included), `2 * half + 1` of them; `groups`: for the voltages, then
    /// the currents if any, the three channels of the records and the engineering value of one count.
    #[new]
    #[pyo3(signature = (fs, rate, f0, taps, span, class_p, fill, capacity, channels, groups, idcode, time_base,
                        tolerance_ns, test_mode, head))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        fs: i64, rate: i64, f0: f64, taps: Vec<f64>, span: i64, class_p: bool, fill: i64, capacity: i64,
        channels: usize, groups: Vec<(Vec<usize>, f64)>, idcode: u16, time_base: i64, tolerance_ns: i64,
        test_mode: bool, head: Vec<u8>,
    ) -> PyResult<Self> {
        if fs <= 0 || rate <= 0 || fs % rate != 0 || taps.len().is_multiple_of(2) || span < 0 || capacity <= 0 {
            return Err(PyValueError::new_err("bad rates, taps, span or capacity"));
        }
        if f0 <= 0.0 || (fs as f64 / f0).fract() != 0.0 {
            return Err(PyValueError::new_err("fs must be a multiple of f0"));
        }
        if groups.is_empty() || groups.len() > 2 || head.len() != 2 {
            return Err(PyValueError::new_err("one or two groups of channels, a header of two octets"));
        }
        let pc = (fs as f64 / f0) as usize;
        let reference = (0..pc)
            .map(|m| {
                let th = TWO_PI * m as f64 / pc as f64;
                C { re: th.cos(), im: -th.sin() }
            })
            .collect();
        let a = C { re: (TWO_PI / 3.0).cos(), im: (TWO_PI / 3.0).sin() };
        let half = (taps.len() / 2) as i64;
        let est = Estimator { fs, f0, taps, half, span, class_p, reference, a, a2: a.mul(a) };
        let step = fs / rate;
        let reach = est.reach();
        let mut gs = Vec::new();
        for (cols, lsb) in groups {
            if cols.len() != 3 || cols.iter().any(|&c| c >= channels) {
                return Err(PyValueError::new_err("each group is three channels of the records"));
            }
            gs.push(Group {
                cols: [cols[0], cols[1], cols[2]],
                lsb,
                buf: vec![[f64::NAN; 3]; capacity as usize],
                cap: capacity,
                started: false,
                base: 0,
                next: 0,
                centre: 0,
                step,
                keep: 2 * reach + step + 1,
                reach,
                fill,
                marked: None,
                filled: VecDeque::new(),
                counters: Counters::default(),
            });
        }
        Ok(PhasorUnit {
            est,
            groups: gs,
            time: TimeCheck {
                tolerance_ns,
                error_ns: None,
                synch: 0,
                lost_ns: None,
                now_ns: 0,
                last_ts: None,
                mins: VecDeque::new(),
            },
            channels,
            idcode,
            time_base,
            head: [head[0], head[1]],
            test_mode,
            smp_synch: 0,
            simulation: false,
            frames: 0,
        })
    }

    /// Records of the stream (`open61850.sv_receiver`'s layout); the data frames of the reports they complete,
    /// one after the other in one `bytes` (each `frame_size` octets).
    fn feed<'py>(&mut self, py: Python<'py>, records: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let size = HEADER + 8 * self.channels;
        if !records.len().is_multiple_of(size) {
            return Err(PyValueError::new_err("not whole records"));
        }
        let out = py.detach(|| self.take(records, size));
        Ok(PyBytes::new(py, &out))
    }

    /// Samples still to come before the next report (at least 1).
    fn need(&self) -> i64 {
        self.groups[0].need()
    }

    #[getter]
    fn frame_size(&self) -> usize {
        14 + 2 + 8 * 4 * self.groups.len() + 8 + 2
    }

    /// Each group's counters: (frames, samples, missing, late, filled, reports, invalid_reports).
    fn counters(&self) -> Vec<(u64, u64, u64, u64, u64, u64, u64)> {
        self.groups
            .iter()
            .enumerate()
            .map(|(k, g)| {
                let c = g.counters;
                (if k == 0 { self.frames } else { 0 }, c.samples, c.missing, c.late, c.filled, c.reports, c.invalid_reports)
            })
            .collect()
    }

    #[getter]
    fn error_ns(&self) -> Option<i64> {
        self.time.error_ns
    }

    #[getter]
    fn synchronised(&self) -> bool {
        self.time.synchronised()
    }

    #[getter]
    fn smp_synch(&self) -> u8 {
        self.smp_synch
    }

    #[getter]
    fn simulation(&self) -> bool {
        self.simulation
    }
}

impl PhasorUnit {
    fn take(&mut self, records: &[u8], size: usize) -> Vec<u8> {
        let n = records.len() / size;
        if n == 0 {
            return Vec::new();
        }
        let fs = self.est.fs;
        let ch = self.channels;
        let mut ts = Vec::with_capacity(n);
        let mut labels = Vec::with_capacity(n);
        let mut index = Vec::with_capacity(n);
        let mut last_flags = 0u8;
        for r in records.chunks_exact(size) {
            let t = i64::from_ne_bytes(r[0..8].try_into().unwrap());
            let smp = u16::from_ne_bytes(r[8..10].try_into().unwrap()) as i64;
            self.smp_synch = r[10];
            last_flags = r[11];
            let second = (t as f64 / NS as f64 - smp as f64 / fs as f64).round_ties_even() as i64;
            ts.push(t);
            labels.push(second * NS + smp * NS / fs);
            index.push(second * fs + smp);
        }
        self.frames += n as u64;
        self.time.update(&ts, &labels, self.smp_synch);
        self.simulation = last_flags & FLAG_SIMULATION != 0;
        for (k, r) in records.chunks_exact(size).enumerate() {
            let flags = r[11];
            for g in self.groups.iter_mut() {
                let mut v = [0.0; 3];
                for (j, &col) in g.cols.iter().enumerate() {
                    let o = HEADER + 4 * col;
                    let value = i32::from_ne_bytes(r[o..o + 4].try_into().unwrap()) as f64;
                    let q = HEADER + 4 * ch + 4 * col;
                    let quality = u32::from_ne_bytes(r[q..q + 4].try_into().unwrap());
                    v[j] = if quality == QUALITY_MISSING && flags & FLAG_CHANNELS != 0 { f64::NAN } else { value * g.lsb };
                }
                g.add(index[k], v);
            }
        }
        let (first, rest) = self.groups.split_at_mut(1);
        let currents: Vec<(i64, Measurement, bool)> = match rest.first_mut() {
            Some(g) => g.ready(&self.est),
            None => Vec::new(),
        };
        let voltages = first[0].ready(&self.est);
        let mut out = Vec::with_capacity(voltages.len() * self.frame_size());
        for (c, m, modified) in voltages {
            let mi = currents.iter().find(|(ci, _, _)| *ci == c);
            let imod = mi.is_some_and(|x| x.2);
            self.frame(&mut out, c, &m, mi.map(|x| &x.1), modified || imod);
        }
        out
    }

    fn frame(&mut self, out: &mut Vec<u8>, centre: i64, m: &Measurement, mi: Option<&Measurement>, modified: bool) {
        let valid = !(m.frequency.is_nan() || m.phases.iter().any(|p| p.abs().is_nan()));
        let mut phasors: Vec<C> = m.phases.to_vec();
        phasors.push(m.positive);
        if self.groups.len() > 1 {
            match mi {
                Some(i) => {
                    phasors.extend_from_slice(&i.phases);
                    phasors.push(i.positive);
                }
                None => phasors.extend([C::nan(); 4]),
            }
        }
        let mut stat = if modified { STAT_MODIFIED } else { 0 };
        if self.test_mode && self.simulation {
            stat |= STAT_TEST;
        }
        if !valid {
            stat |= STAT_INVALID;
        }
        stat |= self.time.stat();
        let fs = self.est.fs;
        let (sec, k) = (centre.div_euclid(fs), centre.rem_euclid(fs));
        let frac = k * self.time_base / fs;
        let quality = self.time.message_quality() as u32;
        let start = out.len();
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&(self.frame_size() as u16).to_be_bytes());
        out.extend_from_slice(&self.idcode.to_be_bytes());
        out.extend_from_slice(&(sec as u32).to_be_bytes());
        out.extend_from_slice(&((quality & 0xFF) << 24 | (frac as u32 & 0xFF_FFFF)).to_be_bytes());
        out.extend_from_slice(&stat.to_be_bytes());
        for p in &phasors {
            out.extend_from_slice(&(p.abs() as f32).to_be_bytes());
            out.extend_from_slice(&(p.arg() as f32).to_be_bytes());
        }
        out.extend_from_slice(&(m.frequency as f32).to_be_bytes());
        out.extend_from_slice(&(m.rocof as f32).to_be_bytes());
        let c = crc(&out[start..]);
        out.extend_from_slice(&c.to_be_bytes());
        let g = &mut self.groups[0].counters;
        g.reports += 1;
        if !valid {
            g.invalid_reports += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_is_ccitt_from_ffff() {
        assert_eq!(crc(b"123456789"), 0x29B1);
    }

    #[test]
    fn remainder_is_ieee() {
        assert!((ieee_remainder(0.1) - 0.1).abs() < 1e-15);
        assert!((ieee_remainder(TWO_PI + 0.5) - 0.5).abs() < 1e-12);
        assert!((ieee_remainder(TWO_PI - 0.5) + 0.5).abs() < 1e-12);
    }
}

// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! The receiver of `open61850.sv_receiver`: SV frames of a few streams kept
//! as fixed-size records of samples, read from a capture's TPACKET_V2 ring by
//! a thread of its own (Linux) or fed by hand.
//!
//! A record, in native byte order: `ts_ns: i64, smp_cnt: u16, smp_synch: u8,
//! flags: u8, conf_rev: u32`, then `channels` INT32 values and `channels`
//! qualities (the Python module's notes).

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use open61850_core::sv;
use pyo3::exceptions::{PyIndexError, PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

const FLAG_SIMULATION: u8 = 1;
const FLAG_CHANNELS: u8 = 2;
const QUALITY_MISSING: u32 = 1;
const HEADER: usize = 16;

/// A frame's records (stream, octets) until its PDU has decoded, and records to reuse.
type Scratch = (Vec<(usize, Vec<u8>)>, Vec<Vec<u8>>);

struct Buf {
    data: Vec<u8>,
    count: usize,
}

#[derive(Default)]
struct Counters {
    frames: AtomicU64,
    records: AtomicU64,
    other: AtomicU64,
    not_sv: AtomicU64,
    malformed: AtomicU64,
    overflows: AtomicU64,
}

struct Shared {
    ids: Vec<Vec<u8>>,
    channels: usize,
    capacity: usize,
    bufs: Vec<Mutex<Buf>>,
    // each buffer's count, read without its lock by wait()'s condition
    counts: Vec<AtomicUsize>,
    needs: Vec<AtomicUsize>,
    waiting: AtomicBool,
    signal: Mutex<()>,
    cond: Condvar,
    counters: Counters,
    stop: AtomicBool,
}

impl Shared {
    fn record_size(&self) -> usize {
        HEADER + 8 * self.channels
    }

    fn ready(&self) -> bool {
        self.counts.iter().zip(&self.needs).any(|(c, n)| c.load(Ordering::SeqCst) >= n.load(Ordering::SeqCst))
    }

    /// One frame captured at `ts_ns`; the records kept. `scratch` holds a
    /// frame's records until the whole PDU has decoded.
    fn on_frame(&self, raw: &[u8], ts_ns: i64, scratch: &mut Vec<(usize, Vec<u8>)>, spare: &mut Vec<Vec<u8>>) -> usize {
        let c = &self.counters;
        c.frames.fetch_add(1, Ordering::Relaxed);
        let n = self.channels;
        let size = self.record_size();
        for (_, r) in scratch.drain(..) {
            spare.push(r);
        }
        let mut bad_sample = false;
        let decoded = sv::decode_frame_with(raw, |_, asdu| {
            let Some(k) = self.ids.iter().position(|id| id.as_slice() == asdu.sv_id) else { return };
            let mut rec = spare.pop().unwrap_or_default();
            rec.clear();
            rec.reserve(size);
            rec.extend_from_slice(&ts_ns.to_ne_bytes());
            rec.extend_from_slice(&asdu.smp_cnt.to_ne_bytes());
            rec.push(asdu.smp_synch);
            rec.push(0); // flags, set below
            rec.extend_from_slice(&asdu.conf_rev.to_ne_bytes());
            let Ok(samples) = sv::int32_samples(asdu.sample) else {
                bad_sample = true;
                spare.push(rec);
                return;
            };
            let mut quals = [0u32; 64];
            let mut qv: Vec<u32> = Vec::new();
            let q: &mut [u32] = if n <= quals.len() {
                &mut quals[..n]
            } else {
                qv.resize(n, 0);
                &mut qv
            };
            let mut got = 0usize;
            for (v, qual) in samples {
                if got < n {
                    rec.extend_from_slice(&v.to_ne_bytes());
                    q[got] = qual;
                }
                got += 1;
            }
            for slot in q.iter_mut().skip(got.min(n)) {
                rec.extend_from_slice(&0i32.to_ne_bytes());
                *slot = QUALITY_MISSING;
            }
            for qual in q.iter() {
                rec.extend_from_slice(&qual.to_ne_bytes());
            }
            if got != n {
                rec[11] |= FLAG_CHANNELS;
            }
            scratch.push((k, rec));
        });
        let frame = match decoded {
            Ok(Some((frame, _))) if !bad_sample => frame,
            Ok(None) => {
                c.not_sv.fetch_add(1, Ordering::Relaxed);
                return 0;
            }
            _ => {
                c.malformed.fetch_add(1, Ordering::Relaxed);
                return 0;
            }
        };
        if scratch.is_empty() {
            c.other.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        let simulation = frame.header.reserved1 & 0x8000 != 0;
        let mut kept = 0usize;
        for (k, rec) in scratch.iter_mut() {
            if simulation {
                rec[11] |= FLAG_SIMULATION;
            }
            let mut b = self.bufs[*k].lock().unwrap();
            if b.count >= self.capacity {
                c.overflows.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            b.data.extend_from_slice(rec);
            b.count += 1;
            self.counts[*k].store(b.count, Ordering::SeqCst);
            kept += 1;
        }
        c.records.fetch_add(kept as u64, Ordering::Relaxed);
        if kept > 0 && self.waiting.load(Ordering::SeqCst) && self.ready() {
            let _g = self.signal.lock().unwrap();
            self.cond.notify_all();
        }
        kept
    }
}

struct Running {
    handle: JoinHandle<usize>,
}

#[pyclass(module = "open61850_rt")]
pub struct Receiver {
    shared: Arc<Shared>,
    running: Mutex<Option<Running>>,
    cpu: Option<usize>,
    rt_priority: Option<i32>,
    // feed()'s scratch: Python calls it from one thread at a time
    scratch: Mutex<Scratch>,
}

#[pymethods]
impl Receiver {
    #[new]
    #[pyo3(signature = (sv_ids, channels, capacity, cpu=None, rt_priority=None))]
    fn new(sv_ids: Vec<Vec<u8>>, channels: usize, capacity: usize, cpu: Option<usize>, rt_priority: Option<i32>) -> PyResult<Self> {
        if sv_ids.is_empty() || channels == 0 || capacity == 0 {
            return Err(PyValueError::new_err("streams, channels and capacity must not be empty"));
        }
        let n = sv_ids.len();
        let size = HEADER + 8 * channels;
        Ok(Receiver {
            shared: Arc::new(Shared {
                ids: sv_ids,
                channels,
                capacity,
                bufs: (0..n).map(|_| Mutex::new(Buf { data: Vec::with_capacity(size * 1024), count: 0 })).collect(),
                counts: (0..n).map(|_| AtomicUsize::new(0)).collect(),
                needs: (0..n).map(|_| AtomicUsize::new(usize::MAX)).collect(),
                waiting: AtomicBool::new(false),
                signal: Mutex::new(()),
                cond: Condvar::new(),
                counters: Counters::default(),
                stop: AtomicBool::new(false),
            }),
            running: Mutex::new(None),
            cpu,
            rt_priority,
            scratch: Mutex::new((Vec::new(), Vec::new())),
        })
    }

    /// One frame by hand, captured at `ts_ns`; the records kept.
    fn feed(&self, raw: &[u8], ts_ns: i64) -> usize {
        let mut s = self.scratch.lock().unwrap();
        let (scratch, spare) = &mut *s;
        self.shared.on_frame(raw, ts_ns, scratch, spare)
    }

    fn pending(&self, stream: usize) -> PyResult<usize> {
        let b = self.shared.bufs.get(stream).ok_or_else(|| PyIndexError::new_err("no such stream"))?;
        Ok(b.lock().unwrap().count)
    }

    fn take<'py>(&self, py: Python<'py>, stream: usize) -> PyResult<Bound<'py, PyBytes>> {
        let b = self.shared.bufs.get(stream).ok_or_else(|| PyIndexError::new_err("no such stream"))?;
        let mut g = b.lock().unwrap();
        let out = PyBytes::new(py, &g.data);
        g.data.clear();
        g.count = 0;
        self.shared.counts[stream].store(0, Ordering::SeqCst);
        Ok(out)
    }

    /// Block until some stream `k` holds `need[k]` records, or `timeout` s (negative: no end); false on timeout.
    fn wait(&self, py: Python<'_>, need: Vec<usize>, timeout: f64) -> PyResult<bool> {
        let sh = &self.shared;
        if need.len() != sh.ids.len() {
            return Err(PyValueError::new_err("one need per stream"));
        }
        let deadline = (timeout >= 0.0).then(|| Instant::now() + Duration::from_secs_f64(timeout));
        let sh = Arc::clone(sh);
        Ok(py.detach(move || {
            let mut g = sh.signal.lock().unwrap();
            for (slot, n) in sh.needs.iter().zip(&need) {
                slot.store(*n, Ordering::SeqCst);
            }
            sh.waiting.store(true, Ordering::SeqCst);
            let met = loop {
                if sh.ready() {
                    break true;
                }
                match deadline {
                    None => g = sh.cond.wait(g).unwrap(),
                    Some(d) => {
                        let now = Instant::now();
                        if now >= d {
                            break false;
                        }
                        g = sh.cond.wait_timeout(g, d - now).unwrap().0;
                    }
                }
            };
            sh.waiting.store(false, Ordering::SeqCst);
            for slot in &sh.needs {
                slot.store(usize::MAX, Ordering::SeqCst);
            }
            met
        }))
    }

    /// Read the TPACKET_V2 ring at address `ring` (`slots` slots of `slot_size` octets, from
    /// `next_slot`) of socket `fd`. The caller keeps the ring mapped until `stop()` returns
    /// (the Python module holds a ctypes view of the mmap, which refuses to close meanwhile).
    #[pyo3(signature = (fd, ring, slot_size, slots, next_slot, outgoing))]
    #[allow(clippy::too_many_arguments)]
    fn start(
        &self,
        py: Python<'_>,
        fd: i32,
        ring: usize,
        slot_size: usize,
        slots: usize,
        next_slot: usize,
        outgoing: bool,
    ) -> PyResult<()> {
        let mut guard = self.running.lock().unwrap();
        if guard.is_some() {
            return Err(PyRuntimeError::new_err("already started"));
        }
        if ring == 0 || slots == 0 || next_slot >= slots || slot_size < 64 {
            return Err(PyValueError::new_err("a ring of slots of at least 64 octets, next_slot inside it"));
        }
        let base = ring;
        let shared = Arc::clone(&self.shared);
        shared.stop.store(false, Ordering::SeqCst);
        let (cpu, prio) = (self.cpu, self.rt_priority);
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let handle = std::thread::Builder::new()
            .name("sv-receiver".into())
            .spawn(move || ring_loop(&shared, fd, base, slot_size, slots, next_slot, outgoing, cpu, prio, tx))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        match py.detach(move || rx.recv()) {
            Ok(Ok(())) => {
                *guard = Some(Running { handle });
                Ok(())
            }
            Ok(Err(msg)) => {
                let _ = handle.join();
                Err(PyOSError::new_err(msg))
            }
            Err(_) => Err(PyRuntimeError::new_err("the receiver thread ended during setup")),
        }
    }

    /// Stop the thread; the slot it would have read next.
    fn stop(&self, py: Python<'_>) -> Option<usize> {
        self.shared.stop.store(true, Ordering::SeqCst);
        let Running { handle } = self.running.lock().unwrap().take()?;
        py.detach(move || handle.join().ok())
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let c = &self.shared.counters;
        let d = PyDict::new(py);
        d.set_item("frames", c.frames.load(Ordering::Relaxed))?;
        d.set_item("records", c.records.load(Ordering::Relaxed))?;
        d.set_item("other", c.other.load(Ordering::Relaxed))?;
        d.set_item("not_sv", c.not_sv.load(Ordering::Relaxed))?;
        d.set_item("malformed", c.malformed.load(Ordering::Relaxed))?;
        d.set_item("overflows", c.overflows.load(Ordering::Relaxed))?;
        Ok(d)
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(r) = self.running.lock().unwrap().take() {
            let _ = r.handle.join();
        }
    }
}

const TP_STATUS_USER: u32 = 1;
const TP_STATUS_KERNEL: u32 = 0;
const PACKET_OUTGOING: u8 = 4;

#[cfg(target_os = "linux")]
fn setup(cpu: Option<usize>, prio: Option<i32>) -> Result<(), String> {
    // SAFETY: affinity and scheduling of the calling thread.
    unsafe {
        if let Some(cpu) = cpu {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(cpu, &mut set);
            if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                return Err(format!("pin to CPU {cpu}: {}", std::io::Error::last_os_error()));
            }
        }
        if let Some(p) = prio {
            let param = libc::sched_param { sched_priority: p };
            let rc = libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_FIFO, &param);
            if rc != 0 {
                return Err(format!("SCHED_FIFO priority {p}: {}", std::io::Error::from_raw_os_error(rc)));
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn setup(_cpu: Option<usize>, _prio: Option<i32>) -> Result<(), String> {
    Err("the receiver's thread reads an AF_PACKET ring: Linux only".into())
}

#[allow(clippy::too_many_arguments)]
fn ring_loop(
    sh: &Shared,
    fd: i32,
    base: usize,
    slot_size: usize,
    slots: usize,
    mut slot: usize,
    outgoing: bool,
    cpu: Option<usize>,
    prio: Option<i32>,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) -> usize {
    if let Err(msg) = setup(cpu, prio) {
        let _ = ready.send(Err(msg));
        return slot;
    }
    let _ = ready.send(Ok(()));
    let mut scratch = Vec::new();
    let mut spare = Vec::new();
    while !sh.stop.load(Ordering::Relaxed) {
        let hdr = (base + slot * slot_size) as *mut u8;
        // SAFETY: the slot lies inside the ring the caller keeps mapped until
        // stop() has joined this thread; tp_status is the word the kernel and this thread
        // hand the slot over with, read and written atomically.
        let status = unsafe { &*(hdr as *const std::sync::atomic::AtomicU32) };
        if status.load(Ordering::Acquire) & TP_STATUS_USER == 0 {
            poll_once(fd);
            continue;
        }
        // SAFETY: a slot owned by user space holds a tpacket2_hdr, then the
        // frame at tp_mac for tp_snaplen octets, within the slot.
        unsafe {
            let u32_at = |off: usize| std::ptr::read_unaligned(hdr.add(off) as *const u32);
            let u16_at = |off: usize| std::ptr::read_unaligned(hdr.add(off) as *const u16);
            let snaplen = u32_at(8) as usize;
            let mac = u16_at(12) as usize;
            let (sec, nsec) = (u32_at(16) as i64, u32_at(20) as i64);
            let is_out = *hdr.add(32 + 10) == PACKET_OUTGOING;
            if (outgoing || !is_out) && mac + snaplen <= slot_size {
                let frame = std::slice::from_raw_parts(hdr.add(mac), snaplen);
                sh.on_frame(frame, sec * 1_000_000_000 + nsec, &mut scratch, &mut spare);
            }
        }
        status.store(TP_STATUS_KERNEL, Ordering::Release);
        slot = (slot + 1) % slots;
    }
    slot
}

#[cfg(target_os = "linux")]
fn poll_once(fd: i32) {
    let mut p = libc::pollfd { fd, events: libc::POLLIN | libc::POLLERR, revents: 0 };
    // SAFETY: one valid pollfd; 100 ms so that stop() is seen.
    unsafe { libc::poll(&mut p, 1, 100) };
}

#[cfg(not(target_os = "linux"))]
fn poll_once(_fd: i32) {
    std::thread::sleep(Duration::from_millis(100));
}

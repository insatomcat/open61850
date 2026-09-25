// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Real-time Sampled Values engine of open61850.
//!
//! Python (`open61850.sv_publisher`) prepares one frame template per stream
//! and the positions of smpCnt and of the samples in each ASDU; this engine
//! fills them and sends the frames on absolute `CLOCK_REALTIME` deadlines,
//! one `sendmmsg` per frame period for every stream. The sample values are
//! computed exactly as `open61850.sv_publisher.render_frame` does (same
//! floating-point operations in the same order, ties rounded to even), so
//! both produce the same bytes.

use std::f64::consts::PI;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use open61850_core::sv;
use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

const NS_PER_S: i64 = 1_000_000_000;

#[derive(Clone)]
struct Wave {
    amplitude: f64,
    phase_deg: f64,
    freq_hz: f64,
    offset: f64,
    scale: f64,
    quality: u32,
}

impl Wave {
    fn value(&self, second: i64, smp: i64, rate: i64) -> i32 {
        let x = if self.freq_hz == 0.0 || self.amplitude == 0.0 {
            self.offset
        } else {
            let cycles = (self.freq_hz * second as f64) % 1.0 + self.freq_hz * smp as f64 / rate as f64;
            self.offset + self.amplitude * (2.0 * PI * cycles + self.phase_deg.to_radians()).sin()
        };
        let v = (x * self.scale).round_ties_even();
        v.clamp(i32::MIN as f64, i32::MAX as f64) as i32
    }
}

#[derive(Clone)]
struct Fault {
    waves: Vec<Wave>,
    cycle_s: i64,
    offset_s: i64,
    start_smp: i64,
    duration_s: Option<f64>,
}

impl Fault {
    fn active(&self, second: i64, smp: i64, rate: i64) -> bool {
        let cycle = self.cycle_s.max(1);
        let period = cycle * rate;
        let start = self.offset_s.rem_euclid(cycle) * rate + self.start_smp.clamp(0, rate - 1);
        let length = match self.duration_s {
            None => period / 2,
            Some(d) => ((d * rate as f64).round_ties_even() as i64).clamp(0, period),
        };
        (second * rate + smp - start).rem_euclid(period) < length
    }
}

/// Recorded samples played instead of the waves (`open61850.sv_publisher.Playback`).
#[derive(Clone)]
struct Playback {
    values: Vec<i32>,
    qualities: Option<Vec<u32>>,
    channels: usize,
    start: i64,          // absolute sample number (second * rate + smpCnt) of row 0
    period: Option<i64>, // in samples, when the recording repeats
}

impl Playback {
    fn rows(&self) -> i64 {
        (self.values.len() / self.channels) as i64
    }

    fn index(&self, second: i64, smp: i64, rate: i64) -> Option<usize> {
        let mut i = second * rate + smp - self.start;
        if let Some(p) = self.period {
            i = i.rem_euclid(p);
        }
        (0..self.rows()).contains(&i).then_some(i as usize)
    }
}

#[derive(Clone)]
struct Stream {
    frame: Vec<u8>,
    smp_offsets: Vec<usize>,
    sample_offsets: Vec<usize>,
    waves: Vec<Wave>,
    fault: Option<Fault>,
    playback: Option<Playback>,
}

impl Stream {
    fn render(&self, buf: &mut [u8], second: i64, first_smp: i64, rate: i64) {
        for (i, (&smp_at, &sample_at)) in self.smp_offsets.iter().zip(&self.sample_offsets).enumerate() {
            let n = first_smp + i as i64;
            let sec = second + n.div_euclid(rate);
            let smp = n.rem_euclid(rate);
            buf[smp_at..smp_at + 2].copy_from_slice(&(smp as u16).to_be_bytes());
            if let Some((p, row)) = self.playback.as_ref().and_then(|p| p.index(sec, smp, rate).map(|r| (p, r))) {
                for ch in 0..p.channels {
                    let at = sample_at + 8 * ch;
                    let quality = match &p.qualities {
                        Some(q) => q[row * p.channels + ch],
                        None => self.waves[ch].quality,
                    };
                    buf[at..at + 4].copy_from_slice(&p.values[row * p.channels + ch].to_be_bytes());
                    buf[at + 4..at + 8].copy_from_slice(&quality.to_be_bytes());
                }
                continue;
            }
            let waves = match &self.fault {
                Some(f) if f.active(sec, smp, rate) => &f.waves,
                _ => &self.waves,
            };
            for (ch, w) in waves.iter().enumerate() {
                let at = sample_at + 8 * ch;
                buf[at..at + 4].copy_from_slice(&w.value(sec, smp, rate).to_be_bytes());
                buf[at + 4..at + 8].copy_from_slice(&w.quality.to_be_bytes());
            }
        }
    }
}

#[derive(Default)]
struct Counters {
    stop: AtomicBool,
    frames_sent: AtomicU64,
    send_errors: AtomicU64,
    late_frames: AtomicU64,
    max_lateness_ns: AtomicI64,
}

struct Config {
    iface: String,
    rate: i64,
    asdus: i64,
    streams: Vec<Stream>,
    start_second: i64,
    rt_priority: Option<i32>,
    cpu: Option<usize>,
}

/// The engine behind `open61850.sv.Publisher(engine="native")`.
///
/// `Engine(iface, rate, asdus_per_frame, streams, start_second, rt_priority, cpu)`,
/// `streams` being the dicts built by `open61850.sv_publisher._native_streams`.
#[pyclass(module = "open61850_rt")]
struct Engine {
    config: Arc<Config>,
    counters: Arc<Counters>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

fn item<'py>(d: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    d.get_item(key)?.ok_or_else(|| PyValueError::new_err(format!("stream without {key}")))
}

fn waves_from(obj: &Bound<'_, PyAny>) -> PyResult<Vec<Wave>> {
    let raw: Vec<(f64, f64, f64, f64, f64, u32)> = obj.extract()?;
    Ok(raw
        .into_iter()
        .map(|(amplitude, phase_deg, freq_hz, offset, scale, quality)| Wave {
            amplitude,
            phase_deg,
            freq_hz,
            offset,
            scale,
            quality,
        })
        .collect())
}

fn stream_from(obj: &Bound<'_, PyAny>) -> PyResult<Stream> {
    let d = obj.downcast::<PyDict>()?;
    let frame: Vec<u8> = item(d, "frame")?.extract()?;
    let smp_offsets: Vec<usize> = item(d, "smp_cnt_offsets")?.extract()?;
    let sample_offsets: Vec<usize> = item(d, "sample_offsets")?.extract()?;
    let waves = waves_from(&item(d, "waves")?)?;
    let fault_obj = item(d, "fault")?;
    let fault = if fault_obj.is_none() {
        None
    } else {
        let f = fault_obj.downcast::<PyDict>()?;
        Some(Fault {
            waves: waves_from(&item(f, "waves")?)?,
            cycle_s: item(f, "cycle_s")?.extract()?,
            offset_s: item(f, "offset_s")?.extract()?,
            start_smp: item(f, "start_smp")?.extract()?,
            duration_s: item(f, "duration_s")?.extract()?,
        })
    };
    let playback = match d.get_item("playback")? {
        Some(obj) if !obj.is_none() => Some(playback_from(obj.downcast::<PyDict>()?)?),
        _ => None,
    };
    if smp_offsets.len() != sample_offsets.len() || smp_offsets.is_empty() {
        return Err(PyValueError::new_err("smp_cnt_offsets and sample_offsets must match"));
    }
    let channels = waves.len();
    if fault.as_ref().is_some_and(|f| f.waves.len() != channels) {
        return Err(PyValueError::new_err("the fault waves must have as many channels as the stream"));
    }
    for (&s, &a) in smp_offsets.iter().zip(&sample_offsets) {
        if s + 2 > frame.len() || a + 8 * channels > frame.len() {
            return Err(PyValueError::new_err("offset outside the frame"));
        }
    }
    if playback.as_ref().is_some_and(|p| p.channels != channels) {
        return Err(PyValueError::new_err("the playback must have as many channels as the stream"));
    }
    Ok(Stream { frame, smp_offsets, sample_offsets, waves, fault, playback })
}

fn ints<T>(bytes: &[u8], convert: fn([u8; 4]) -> T) -> PyResult<Vec<T>> {
    if bytes.len() % 4 != 0 {
        return Err(PyValueError::new_err("playback data must be 32-bit integers"));
    }
    Ok(bytes.chunks_exact(4).map(|c| convert([c[0], c[1], c[2], c[3]])).collect())
}

fn playback_from(d: &Bound<'_, PyDict>) -> PyResult<Playback> {
    let channels: usize = item(d, "channels")?.extract()?;
    let values = ints(&item(d, "values")?.extract::<Vec<u8>>()?, i32::from_ne_bytes)?;
    let qualities_obj = item(d, "qualities")?;
    let qualities = if qualities_obj.is_none() {
        None
    } else {
        Some(ints(&qualities_obj.extract::<Vec<u8>>()?, u32::from_ne_bytes)?)
    };
    if channels == 0 || values.is_empty() || values.len() % channels != 0 {
        return Err(PyValueError::new_err("playback values must fill whole rows of channels"));
    }
    if qualities.as_ref().is_some_and(|q| q.len() != values.len()) {
        return Err(PyValueError::new_err("playback qualities must match the values"));
    }
    let period: Option<i64> = item(d, "period")?.extract()?;
    if period.is_some_and(|p| p <= 0) {
        return Err(PyValueError::new_err("playback period must be positive"));
    }
    Ok(Playback { values, qualities, channels, start: item(d, "start")?.extract()?, period })
}

#[pymethods]
impl Engine {
    #[new]
    #[pyo3(signature = (iface, rate, asdus_per_frame, streams, start_second, rt_priority=None, cpu=None))]
    fn new(
        iface: String,
        rate: i64,
        asdus_per_frame: i64,
        streams: Vec<Bound<'_, PyAny>>,
        start_second: i64,
        rt_priority: Option<i32>,
        cpu: Option<usize>,
    ) -> PyResult<Self> {
        if rate <= 0 || asdus_per_frame <= 0 || rate % asdus_per_frame != 0 {
            return Err(PyValueError::new_err("rate must be a positive multiple of asdus_per_frame"));
        }
        let streams = streams.iter().map(stream_from).collect::<PyResult<Vec<_>>>()?;
        if streams.iter().any(|s| s.smp_offsets.len() as i64 != asdus_per_frame) {
            return Err(PyValueError::new_err("every template must carry asdus_per_frame ASDUs"));
        }
        Ok(Engine {
            config: Arc::new(Config { iface, rate, asdus: asdus_per_frame, streams, start_second, rt_priority, cpu }),
            counters: Arc::new(Counters::default()),
            thread: Mutex::new(None),
        })
    }

    /// Frame of stream `stream` carrying samples `first_smp`... of UNIX second `second` (for tests).
    fn render<'py>(&self, py: Python<'py>, stream: usize, second: i64, first_smp: i64) -> PyResult<Bound<'py, PyBytes>> {
        let s = self.config.streams.get(stream).ok_or_else(|| PyValueError::new_err("no such stream"))?;
        let mut buf = s.frame.clone();
        s.render(&mut buf, second, first_smp, self.config.rate);
        Ok(PyBytes::new(py, &buf))
    }

    /// Open the socket, then send from a thread of its own until `stop()`.
    fn start(&self, py: Python<'_>) -> PyResult<()> {
        let mut guard = self.thread.lock().unwrap();
        if guard.is_some() {
            return Err(PyRuntimeError::new_err("already started"));
        }
        let fd = open_socket(&self.config.iface).map_err(|e| PyOSError::new_err(e))?;
        let config = Arc::clone(&self.config);
        let counters = Arc::clone(&self.counters);
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let handle = std::thread::Builder::new()
            .name("sv-engine".into())
            .spawn(move || run(fd, &config, &counters, ready_tx))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let setup = py.allow_threads(move || ready_rx.recv());
        match setup {
            Ok(Ok(())) => {
                *guard = Some(handle);
                Ok(())
            }
            Ok(Err(msg)) => {
                let _ = handle.join();
                Err(PyOSError::new_err(msg))
            }
            Err(_) => Err(PyRuntimeError::new_err("the engine thread ended during setup")),
        }
    }

    fn stop(&self, py: Python<'_>) {
        self.counters.stop.store(true, Ordering::SeqCst);
        let handle = self.thread.lock().unwrap().take();
        if let Some(h) = handle {
            py.allow_threads(|| {
                let _ = h.join();
            });
        }
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let c = &self.counters;
        let d = PyDict::new(py);
        d.set_item("frames_sent", c.frames_sent.load(Ordering::Relaxed))?;
        d.set_item("send_errors", c.send_errors.load(Ordering::Relaxed))?;
        d.set_item("late_frames", c.late_frames.load(Ordering::Relaxed))?;
        d.set_item("max_lateness_ns", c.max_lateness_ns.load(Ordering::Relaxed))?;
        Ok(d)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.counters.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}

fn os_error(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

fn open_socket(iface: &str) -> Result<i32, String> {
    let name = std::ffi::CString::new(iface).map_err(|_| "bad interface name".to_string())?;
    // SAFETY: plain libc calls on a fresh socket and a zeroed sockaddr_ll.
    unsafe {
        let index = libc::if_nametoindex(name.as_ptr());
        if index == 0 {
            return Err(os_error(&format!("interface {iface}")));
        }
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0);
        if fd < 0 {
            return Err(os_error("AF_PACKET socket"));
        }
        let mut addr: libc::sockaddr_ll = std::mem::zeroed();
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = index as i32;
        let len = std::mem::size_of::<libc::sockaddr_ll>() as u32;
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len) != 0 {
            let e = os_error("bind");
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

fn setup_thread(config: &Config) -> Result<(), String> {
    // SAFETY: affinity and scheduling of the calling thread.
    unsafe {
        if let Some(cpu) = config.cpu {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(cpu, &mut set);
            if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                return Err(os_error(&format!("pin to CPU {cpu}")));
            }
        }
        if let Some(prio) = config.rt_priority {
            let param = libc::sched_param { sched_priority: prio };
            let rc = libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_FIFO, &param);
            if rc != 0 {
                return Err(format!("SCHED_FIFO priority {prio}: {}", std::io::Error::from_raw_os_error(rc)));
            }
        }
    }
    Ok(())
}

fn now_ns() -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer to a timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts.tv_sec * NS_PER_S + ts.tv_nsec
}

fn sleep_until(target_ns: i64) {
    let ts = libc::timespec { tv_sec: target_ns.div_euclid(NS_PER_S), tv_nsec: target_ns.rem_euclid(NS_PER_S) };
    loop {
        // SAFETY: valid timespec; absolute sleep, restarted on EINTR.
        let rc = unsafe { libc::clock_nanosleep(libc::CLOCK_REALTIME, libc::TIMER_ABSTIME, &ts, std::ptr::null_mut()) };
        if rc != libc::EINTR {
            break;
        }
    }
}

fn run(fd: i32, config: &Config, counters: &Counters, ready: mpsc::Sender<Result<(), String>>) {
    if let Err(msg) = setup_thread(config) {
        let _ = ready.send(Err(msg));
        // SAFETY: the socket belongs to this thread.
        unsafe { libc::close(fd) };
        return;
    }
    let _ = ready.send(Ok(()));

    let rate = config.rate;
    let asdus = config.asdus;
    let frames_per_second = rate / asdus;
    let mut buffers: Vec<Vec<u8>> = config.streams.iter().map(|s| s.frame.clone()).collect();
    let mut iovecs: Vec<libc::iovec> = buffers
        .iter_mut()
        .map(|b| libc::iovec { iov_base: b.as_mut_ptr() as *mut libc::c_void, iov_len: b.len() })
        .collect();
    // SAFETY: zeroed mmsghdr are valid; each points at one iovec that outlives the loop.
    let mut msgs: Vec<libc::mmsghdr> = (0..iovecs.len()).map(|_| unsafe { std::mem::zeroed() }).collect();
    for (m, iov) in msgs.iter_mut().zip(iovecs.iter_mut()) {
        m.msg_hdr.msg_iov = iov as *mut libc::iovec;
        m.msg_hdr.msg_iovlen = 1;
    }
    let period_ns = NS_PER_S * asdus / rate;

    let mut k: i64 = 0;
    while !counters.stop.load(Ordering::Relaxed) {
        let second = config.start_second + k / frames_per_second;
        let index = k % frames_per_second;
        let target = second * NS_PER_S + index * asdus * NS_PER_S / rate;
        // Fill before sleeping: the frame is ready when its time comes.
        for (stream, buf) in config.streams.iter().zip(buffers.iter_mut()) {
            stream.render(buf, second, index * asdus, rate);
        }
        sleep_until(target);
        let lateness = now_ns() - target;
        let mut sent = 0usize;
        while sent < msgs.len() {
            // SAFETY: msgs[sent..] point at valid buffers of this thread.
            let n = unsafe { libc::sendmmsg(fd, msgs[sent..].as_mut_ptr(), (msgs.len() - sent) as u32, 0) };
            if n <= 0 {
                counters.send_errors.fetch_add((msgs.len() - sent) as u64, Ordering::Relaxed);
                break;
            }
            sent += n as usize;
        }
        counters.frames_sent.fetch_add(sent as u64, Ordering::Relaxed);
        counters.max_lateness_ns.fetch_max(lateness, Ordering::Relaxed);
        if lateness > period_ns {
            counters.late_frames.fetch_add(sent as u64, Ordering::Relaxed);
        }
        k += 1;
    }
    // SAFETY: the socket belongs to this thread.
    unsafe { libc::close(fd) };
}

// --- SV decoding (open61850-core), exposed to compare it with open61850.sv ---

type DecodedPdu<'py> = (Option<Bound<'py, PyBytes>>, Vec<Bound<'py, PyDict>>);

fn pdu_to_py<'py>(py: Python<'py>, pdu: &sv::SvPdu<'_>) -> PyResult<DecodedPdu<'py>> {
    let bytes = |b: &[u8]| PyBytes::new(py, b);
    let mut asdus = Vec::with_capacity(pdu.len());
    for a in pdu.asdus() {
        let d = PyDict::new(py);
        d.set_item("sv_id", bytes(a.sv_id))?;
        d.set_item("dat_set", a.dat_set.map(bytes))?;
        d.set_item("smp_cnt", a.smp_cnt)?;
        d.set_item("conf_rev", a.conf_rev)?;
        d.set_item("refr_tm", a.refr_tm.map(|t| (t.seconds, t.fraction, t.quality)))?;
        d.set_item("smp_synch", a.smp_synch)?;
        d.set_item("smp_rate", a.smp_rate)?;
        d.set_item("sample", bytes(a.sample))?;
        d.set_item("smp_mod", a.smp_mod)?;
        d.set_item("gm_identity", a.gm_identity.map(bytes))?;
        asdus.push(d);
    }
    Ok((pdu.security.map(bytes), asdus))
}

/// `(security, [asdu dicts])` of a SavPdu; ValueError when it is invalid (for tests).
#[pyfunction]
fn decode_sv_pdu<'py>(py: Python<'py>, apdu: &[u8]) -> PyResult<DecodedPdu<'py>> {
    let pdu = sv::decode_pdu(apdu).map_err(|e| PyValueError::new_err(e.to_string()))?;
    pdu_to_py(py, &pdu)
}

/// `None` for a frame that is not SV, else `(frame dict, security, [asdu dicts])` (for tests).
#[pyfunction]
fn decode_sv_frame<'py>(py: Python<'py>, raw: &[u8]) -> PyResult<Option<(Bound<'py, PyDict>, DecodedPdu<'py>)>> {
    let Some((frame, pdu)) = sv::decode_frame(raw).map_err(|e| PyValueError::new_err(e.to_string()))? else {
        return Ok(None);
    };
    let d = PyDict::new(py);
    d.set_item("dst_mac", PyBytes::new(py, &frame.dst_mac))?;
    d.set_item("src_mac", PyBytes::new(py, &frame.src_mac))?;
    d.set_item("vlan_id", frame.vlan_id)?;
    d.set_item("vlan_priority", frame.vlan_priority)?;
    d.set_item("app_id", frame.header.app_id)?;
    d.set_item("reserved1", frame.header.reserved1)?;
    d.set_item("reserved2", frame.header.reserved2)?;
    Ok(Some((d, pdu_to_py(py, &pdu)?)))
}

#[pymodule]
fn open61850_rt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Engine>()?;
    m.add_function(wrap_pyfunction!(decode_sv_pdu, m)?)?;
    m.add_function(wrap_pyfunction!(decode_sv_frame, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

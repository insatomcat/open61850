# open61850-rt

The real-time Sampled Values engine of [open61850](https://github.com/insatomcat/open61850), in Rust, for Linux. Install it with `pip install "open61850[rt]"`. The publisher and the receiver are used through open61850's classes (`open61850.sv.Publisher`, `open61850.sv_receiver.Receiver`); `PhasorUnit` is used directly, as `open61850_rt.PhasorUnit`.

**Publisher.** It sends the frames open61850 prepares (one template per stream, with the positions of smpCnt and of the samples) on absolute `CLOCK_REALTIME` deadlines, one `sendmmsg` per period for every stream, with optional `SCHED_FIFO` priority and CPU pinning. Each sample comes from the stream's playback of recorded samples (a captured SV stream, a COMTRADE record), else from its trajectory of phasors pushed while it runs, else from its periodic fault, else from its waveforms, computed as open61850's Python renderer does, to the octet. A merging unit's clock off true time (offset, drift, smpSynch) shifts the labels and the send times.

**Receiver.** A thread reads a capture's TPACKET_V2 ring, decodes the frames of the streams asked for and keeps their samples as records, without the GIL.

**PhasorUnit.** A PMU's work per report, fed with the receiver's records of one stream: the samples placed in time (gaps, late samples, a time stepping back), the merging unit's time checked, the synchrophasors, frequency and ROCOF of IEC/IEEE 60255-118-1's Annex D (classes P and M, the filter's taps given by the caller), and each report as an IEEE C37.118.2 data frame (polar float phasors, STAT, time quality). It is vpac-wams' Python PMU written again in Rust, whose tests compare the two frame by frame; a report takes 3.2 us in class P where it took 123 in Python.

The `core/` crate of this workspace, `open61850-core`, holds the process bus codecs (Sampled Values decoding, GOOSE encoding and decoding) for real-time callers: `no_std`, no allocation, no unsafe code, the same accepted input and the same output octets as the Python codecs of open61850. `capi/` is their C API, `libopen61850` (see [capi/README.md](https://github.com/insatomcat/open61850/blob/main/native/capi/README.md)), and `fuzz/` fuzzes them.

Apache License 2.0.

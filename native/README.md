# open61850-rt

The real-time Sampled Values engine of [open61850](https://github.com/insatomcat/open61850), in Rust. Install it with `pip install "open61850[rt]"` and use it through `open61850.sv.Publisher`; it has no API of its own to learn.

It sends the frames open61850 prepares (one template per stream, with the positions of smpCnt and of the samples), computing the samples from the waveform parameters, on absolute `CLOCK_REALTIME` deadlines, one `sendmmsg` per period for every stream, with optional `SCHED_FIFO` priority and CPU pinning. Linux only.

Apache License 2.0.

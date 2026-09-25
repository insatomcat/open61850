# open61850

IEC 61850 for Python, under the Apache 2.0 licence: an MMS client (reports, report control blocks, controls), GOOSE and Sampled Values codecs, supervision of GOOSE and SV streams, Sampled Values publication with a real-time engine, an SCL reader, pcap/pcapng files and a Linux capture for the process bus. The library is pure Python (standard library only, Python 3.10 or later); the optional real-time engine is in Rust.

It was written for a test and diagnostic platform of a digital substation process bus, and checked there against real IEDs (a Schneider VMC7 and an ABB SSC600). The other open-source IEC 61850 stack, libiec61850, is GPL; open61850 is an alternative for projects that cannot take a GPL dependency.

**Status**: alpha. The MMS client side and SV publication are what exist and what has been tested; there is no MMS server yet. Until 1.0, minor versions may change the API.

## Installation

```bash
pip install open61850
pip install "open61850[rt]"    # adds the real-time SV engine (Linux wheels, x86_64 and aarch64)
```

## What is in it

| Module | Content |
|--------|---------|
| `open61850.mms` | MMS client over TCP: association (Session, Presentation, ACSE, Initiate) with the negotiated limits honoured, reads and writes, GetNameList, type and data set descriptions, several requests in flight matched by invokeID, reports delivered to callbacks, typed errors |
| `open61850.mms.reference` | IEC 61850 references (`LD/LN.DO.DA [FC]`) and their MMS names; every client method takes either notation |
| `open61850.mms.model` | The server's data model discovered over MMS: logical devices and nodes, data objects and attributes with their functional constraints, control blocks, data sets, types; references resolved against it |
| `open61850.mms.report` | IEC 61850 report decoding driven by the report's own OptFlds and inclusion bit string (segmentation, reason codes, data references) |
| `open61850.mms.rcb` | Report control blocks: status, free instance, reservation (edition 1 and 2 BRCBs, URCBs), enabling with checked writes, release |
| `open61850.mms.control` | Controls: direct and select-before-operate, normal and enhanced security (waits for the CommandTermination, reports the LastApplError AddCause) |
| `open61850.goose` | GOOSE PDUs and frames (IEC 61850-8-1) |
| `open61850.goose_publisher` | GOOSE publication: a new state sent at once then repeated after min time, doubling up to max time, timeAllowedtoLive three times the wait (as libiec61850) |
| `open61850.sv` | Sampled Values PDUs and frames (IEC 61850-9-2, IEC 61869-9), INT32 + quality samples |
| `open61850.supervision` | GOOSE and SV stream supervision, as a subscriber sees it: stNum/sqNum and smpCnt gaps, duplicates, late messages, restarts, timeAllowedtoLive and SV timeouts, configuration, simulation and synchronisation changes |
| `open61850.sv_publisher` | SV publication: streams, waveforms aligned on the UNIX epoch, periodic faults, playback of recorded samples (a captured SV stream, a COMTRADE record), 6I3U / 4I4U data sets, frame templates, `Publisher` (native real-time engine or a Python thread) |
| `open61850.comtrade` | COMTRADE records (IEEE C37.111 1991, 1999, 2013; ASCII, BINARY, BINARY32, FLOAT32): channels in primary or secondary values, sample times, resampling |
| `open61850.ethernet` | Ethernet II and 802.1Q framing with the APPID header |
| `open61850.data` | MMS `Data` values and their BER encoding |
| `open61850.quality` | Quality and TimeQuality in readable form |
| `open61850.scl` | SCL files (CID, ICD, SCD): IEDs, addresses, logical devices, data sets and their members, report, GOOSE and SV control blocks with their multicast addresses, and the data model of the DataTypeTemplates, comparable with the one discovered online |
| `open61850.capture` | GOOSE and SV capture on Linux from an AF_PACKET TPACKET_V3 ring, kernel timestamps, 802.1Q tags restored, no libpcap |
| `open61850.pcap` | pcap and pcapng files (Wireshark, tcpdump), on any OS: reading, and writing classic pcap with nanosecond timestamps |
| `open61850.ber` | ASN.1 BER primitives |

Only `open61850.mms`, `open61850.capture` and the publishers (`GoosePublisher`, SV `Publisher`) do network I/O; `open61850.pcap` reads and writes files. The public names of each module are those of its `__all__`.

## Examples

Discover the data model and read values by their IEC 61850 reference:

```python
from open61850.mms import MmsClient, discover

with MmsClient.connect("192.0.2.10") as client:
    print(client.association.max_outstanding_calling)   # requests the IED accepts at once
    model = discover(client)                             # logical devices, nodes, data, control blocks
    for ref in model.references(fc="MX"):
        print(ref)                                       # IED01_LD0/MMXU1.TotW.mag.f [MX]
    print(client.read("IED01_LD0/LLN0.Mod.stVal[ST]"))  # same as "IED01_LD0/LLN0$ST$Mod$stVal"
    ref = model.resolve("IED01_LD0/MMXU1.TotW.mag.f")    # the FC found in the model
    print(ref, client.read(ref))
```

Subscribe to a buffered report control block:

```python
import queue
from open61850.mms import MmsClient, ObjectName, decode_report, is_report, rcb

reports = queue.Queue()
with MmsClient.connect("192.0.2.10", on_information_report=reports.put) as client:
    instances = [ObjectName(f"LLN0$BR$CB_MEAS{i:02d}", "IED01_LD0") for i in range(1, 4)]
    free = rcb.find_free(client, instances)
    rcb.enable(client, free.rcb)            # default RcbSettings: dchg, qchg, integrity, GI
    try:
        while True:
            message = reports.get()
            if is_report(message):
                report = decode_report(message)
                print(report.rpt_id, report.seq_num, [(e.index, e.value) for e in report.entries])
    finally:
        rcb.disable(client, free.rcb)       # also releases the reservation
```

Operate a breaker (the control model is read from the IED):

```python
from open61850.mms import MmsClient, operate

with MmsClient.connect("192.0.2.10") as client:
    result = operate(client, "IED01_BayLD/CBCSWI1.Pos", False)   # False = open
    print(result)   # control model, ctlNum, CommandTermination, duration
```

A refusal raises `ControlError` with the AddCause of the IED.

Decode GOOSE and SV frames captured on the process bus (Linux, root):

```python
from open61850 import goose, sv
from open61850.capture import PacketCapture

with PacketCapture("eth1") as cap:
    while True:
        frame = cap.recv()
        if frame is None:
            continue
        if (decoded := goose.decode_goose_frame(frame.data)) is not None:
            eth, pdu = decoded
            print(frame.timestamp, pdu.gocb_ref, pdu.st_num, pdu.sq_num)
        elif (decoded := sv.decode_sv_frame(frame.data)) is not None:
            eth, pdu = decoded
            print(frame.timestamp, [(a.sv_id, a.smp_cnt) for a in pdu.asdus])
```

Supervise the GOOSE and SV streams of a Wireshark capture, on any OS (the same code takes the frames of `PacketCapture` live):

```python
from open61850.pcap import read_pcap
from open61850.supervision import BusSupervisor, EventKind, SvSupervisor

bus = BusSupervisor(sv_supervisor=SvSupervisor(sample_rate=4800))
for frame in read_pcap("bus.pcapng"):
    for event in bus.feed(frame):
        if event.kind is not EventKind.NEW_STREAM:
            print(event)        # 1790000002.209167 MU01_SV1 gap: smpCnt 999 -> 1004
print("\n".join(bus.summary()))
```

`GooseSupervisor` and `SvSupervisor` take decoded messages and a reception time, and keep only state: an application can feed them from its own receive loop.

Take a GOOSE control block from an SCL file, or check an IED against its SCL:

```python
from open61850 import scl
from open61850.mms import MmsClient, discover
from open61850.mms.model import compare

(ied,) = scl.load_ieds("IED01.cid")
control = ied.goose_controls[0].goose_control(src_mac="02:00:00:00:00:01")   # for GoosePublisher
with MmsClient.connect("192.0.2.10") as client:
    print(compare(scl.load_model("IED01.cid"), discover(client)))              # [] when they match
```

Publish a GOOSE control block, as a protection relay would (Linux, root):

```python
from open61850.data import BoolData
from open61850.goose_publisher import GooseControl, GoosePublisher

control = GooseControl("IED01_LD0/LLN0$GO$gcbTrip", "IED01_LD0/LLN0$DS_TRIP", app_id=0x0001,
                       dst_mac="01:0c:cd:01:00:01", src_mac="02:00:00:00:00:01", min_time_ms=4, max_time_ms=1000)
with GoosePublisher("eth1", control, [BoolData(False)]) as pub:
    pub.start()                      # stNum 1, repeated every second once settled
    ...
    pub.publish([BoolData(True)])    # trip: stNum 2, sent at once, then after 4, 8, 16... ms
```

Publish Sampled Values, as a merging unit or a simulator would (Linux, root):

```python
from open61850.sv import Publisher, SvStream, Fault, three_phase

stream = SvStream(
    sv_id="MU01_SV1", app_id=0x4000, dst_mac="01:0c:cd:04:00:01", src_mac="02:00:00:00:00:01",
    waves=three_phase(i_peak=10, v_peak=100, i_lag_deg=30),               # 6I3U: Ia Ib Ic Ires In Ih Va Vb Vc
    fault=Fault(three_phase(i_peak=10, v_peak=100, ia_peak=50, va_peak=20), cycle_s=4),  # every 4 s, for 2 s
    conf_rev=1, smp_synch=2, vlan_id=100, vlan_priority=4,
)
with Publisher("eth1", rate=4800, asdus_per_frame=2, rt_priority=50) as pub:
    pub.add(stream)
    pub.start()          # at the next second: smpCnt 0 goes out on the second
    ...
```

Recorded samples can replace the waveforms: a stream captured from a merging unit, or a fault record in COMTRADE, resampled to the publisher's rate. A `Playback` starts at a given second (by default when the publisher starts), once or every few seconds; both engines send it.

```python
from open61850.comtrade import load_comtrade
from open61850.sv import Playback

record = load_comtrade("fault.cfg")
stream.playback = Playback.from_comtrade(
    record, ["IA", "IB", "IC", None, None, None, "VA", "VB", "VC"], rate=4800,
    scales=[w.scale for w in stream.waves], repeat_s=10,    # 9-2LE units: mA and 10 mV
)
```

Waveforms are functions of UNIX time, so several streams, processes or machines on the same clock stay in phase. With `open61850[rt]` the frames are sent by the Rust engine: absolute `CLOCK_REALTIME` deadlines, one `sendmmsg` per period for all streams, optional `SCHED_FIFO` priority and CPU pinning. Without it, a Python thread sends the same frames, with only the precision of `time.sleep` (tests, low rates). Measured on loopback on a Xeon server, 3 streams at 4800 samples/s, `SCHED_FIFO` 50: every sample sent, delay after the nominal sample time median 6 µs, 99th percentile 14 µs, maximum 46 µs over 10 s.

## Command line

```bash
open61850-mms 192.0.2.10 association
open61850-mms 192.0.2.10 domains
open61850-mms 192.0.2.10 browse IED01_LD0 --types
open61850-mms 192.0.2.10 browse --fc MX --flat
open61850-mms 192.0.2.10 compare-scl IED01.cid
open61850-mms 192.0.2.10 rcbs --status
open61850-mms 192.0.2.10 read 'IED01_LD0/LLN0.NamPlt[DC]' 'IED01_LD0/LLN0$ST$Mod$stVal'
open61850-mms 192.0.2.10 dataset IED01_LD0/LLN0.DS_MEAS
open61850-mms 192.0.2.10 subscribe 'IED01_LD0/LLN0$BR$CB_MEAS'
open61850-mms 192.0.2.10 operate IED01_BayLD/CBCSWI1.Pos open
```

`compare-scl station.scd --ied IED01` lists what the IED lacks or has more than its SCL (logical devices and nodes, attributes, control blocks, data sets). `browse` prints the data model (logical devices, logical nodes, data objects with their attributes and functional constraints, control blocks, data sets), with `--flat` one reference per line.

`subscribe` takes a block or a group name without its instance number, picks a free instance, prints the decoded reports and releases the block on Ctrl-C.

```bash
sudo open61850-sv eth1 02:00:00:00:00:01 01:0c:cd:04:00:01 MU01_SV1 --appid 0x4000 --conf-rev 1 \
  --smp-synch 2 --vlan-id 100 --vlan-priority 4 --i-peak 10 --v-peak 100 --phase 30 \
  --fault --fault-i-peak 50 --fault-v-peak 20 --fault-cycle 4 --rt-priority 80
```

`open61850-sv` publishes one SV stream until stopped (`--duration` to stop by itself, `--dump` to print one frame). `--replay-pcap FILE --replay-svid ID` replays a captured stream, `--comtrade FILE.cfg --comtrade-channels IA,IB,IC,,,,VA,VB,VC` a fault record, with `--replay-delay` and `--replay-repeat` in seconds.

```bash
echo true | sudo open61850-goose eth1 02:00:00:00:00:01 01:0c:cd:01:00:01 'IED01_LD0/LLN0$GO$gcbTrip' \
  'IED01_LD0/LLN0$DS_TRIP' false --appid 0x0001 --vlan-id 100
```

`open61850-goose` publishes one GOOSE control block with the initial values given, then one new state per line read on standard input.

```bash
open61850-supervise capture.pcapng --events --sample-rate 4800
sudo open61850-supervise --live eth1
```

`open61850-supervise` prints a line per stream (messages or samples, rate, missed, events), with `--events` every event of a file; with `--live` it prints events as they happen and the summary on Ctrl-C.

## Scope and limits

- No MMS server.
- SV publication sends sinusoids, periodic faults and recorded samples (captures, COMTRADE); samples computed live by the application are to come.
- Not implemented: file services, log control blocks and journals, setting groups, IEC 62351 security.
- The association proposes fixed calling/called AP titles and selectors by default (`AssociationParameters` changes them).
- Tested against two IED families (Schneider VMC7, ABB SSC600) and, in CI, against libiec61850's example servers, publishers and subscriber (model, reads, reports, the four control models, GOOSE both ways, SV); reports of other IEDs are welcome.

## Development

```bash
python -m pip install pytest
python -m pytest
```

The tests need no network. `tools/interop/run.sh` runs the interoperability tests against libiec61850's example programs in Docker (libiec61850 is only run there, as a peer, never linked or shipped). The AF_PACKET capture tests run on Linux as root (`sudo python -m pytest tests/test_capture.py`); on another OS, `docker run --rm --privileged -v "$PWD":/src -w /src python:3.13-slim sh -c "pip install pytest && python -m pytest"`.

Maintainer notes (what the IED captures taught, design decisions) are in [AGENTS.md](AGENTS.md).

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

# open61850

IEC 61850 in pure Python, under the Apache 2.0 licence: an MMS client (reports, report control blocks, controls), GOOSE and Sampled Values codecs, an SCL reader and a Linux capture for the process bus. Standard library only, Python 3.10 or later.

It was written for a test and diagnostic platform of a digital substation process bus, and checked there against real IEDs (a Schneider VMC7 and an ABB SSC600). The other open-source IEC 61850 stack, libiec61850, is GPL; open61850 is an alternative for projects that cannot take a GPL dependency.

**Status**: alpha. The client side is what exists and what has been tested; there is no server yet. Until 1.0, minor versions may change the API.

## Installation

```bash
pip install git+https://github.com/insatomcat/open61850
```

## What is in it

| Module | Content |
|--------|---------|
| `open61850.mms` | MMS client over TCP: association (Session, Presentation, ACSE, Initiate) with the negotiated limits honoured, reads and writes, GetNameList, type and data set descriptions, several requests in flight matched by invokeID, reports delivered to callbacks, typed errors |
| `open61850.mms.report` | IEC 61850 report decoding driven by the report's own OptFlds and inclusion bit string (segmentation, reason codes, data references) |
| `open61850.mms.rcb` | Report control blocks: status, free instance, reservation (edition 1 and 2 BRCBs, URCBs), enabling with checked writes, release |
| `open61850.mms.control` | Controls: direct and select-before-operate, normal and enhanced security (waits for the CommandTermination, reports the LastApplError AddCause) |
| `open61850.goose` | GOOSE PDUs and frames (IEC 61850-8-1) |
| `open61850.sv` | Sampled Values PDUs and frames (IEC 61850-9-2, IEC 61869-9), INT32 + quality samples |
| `open61850.ethernet` | Ethernet II and 802.1Q framing with the APPID header |
| `open61850.data` | MMS `Data` values and their BER encoding |
| `open61850.quality` | Quality and TimeQuality in readable form |
| `open61850.scl` | SCL files: IEDs, addresses, logical devices, report control blocks and data sets |
| `open61850.capture` | GOOSE and SV capture on Linux from an AF_PACKET TPACKET_V3 ring, kernel timestamps, 802.1Q tags restored, no libpcap |
| `open61850.ber` | ASN.1 BER primitives |

Only `open61850.mms` and `open61850.capture` do I/O. The public names of each module are those of its `__all__`.

## Examples

Read a value and list the logical devices:

```python
from open61850.mms import MmsClient, ObjectName, OBJECT_CLASS_DOMAIN

with MmsClient.connect("192.0.2.10") as client:
    print(client.association.max_outstanding_calling)   # requests the IED accepts at once
    print(client.get_name_list(OBJECT_CLASS_DOMAIN))
    print(client.read(ObjectName("LLN0$ST$Mod$stVal", "IED01_LD0")))
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
from open61850.mms import MmsClient, ObjectName, operate

with MmsClient.connect("192.0.2.10") as client:
    result = operate(client, ObjectName("CBCSWI1$CO$Pos", "IED01_BayLD"), False)   # False = open
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

## Command line

```bash
open61850-mms 192.0.2.10 association
open61850-mms 192.0.2.10 domains
open61850-mms 192.0.2.10 rcbs --status
open61850-mms 192.0.2.10 read 'IED01_LD0/LLN0$DC$NamPlt'
open61850-mms 192.0.2.10 dataset 'IED01_LD0/LLN0$DS_MEAS'
open61850-mms 192.0.2.10 subscribe 'IED01_LD0/LLN0$BR$CB_MEAS'
open61850-mms 192.0.2.10 operate 'IED01_BayLD/CBCSWI1$CO$Pos' open
```

`subscribe` takes a block or a group name without its instance number, picks a free instance, prints the decoded reports and releases the block on Ctrl-C.

## Scope and limits

- Client side only: no MMS server, no GOOSE/SV publisher service (the codecs encode, sending frames is up to the application).
- Not implemented: file services, log control blocks and journals, setting groups, IEC 62351 security.
- The association proposes fixed calling/called AP titles and selectors by default (`AssociationParameters` changes them).
- Tested against two IED families so far; reports of other IEDs are welcome.

## Development

```bash
python -m pip install pytest
python -m pytest
```

The tests need no network. The AF_PACKET capture tests run on Linux as root (`sudo python -m pytest tests/test_capture.py`); on another OS, `docker run --rm --privileged -v "$PWD":/src -w /src python:3.13-slim sh -c "pip install pytest && python -m pytest"`.

Maintainer notes (what the IED captures taught, design decisions) are in [AGENTS.md](AGENTS.md).

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

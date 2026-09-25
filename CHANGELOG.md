# Changelog

## Unreleased

- `open61850.pcap`: pcap and pcapng files read on any OS (as the
  `CapturedFrame` of a live capture), classic pcap written with nanosecond
  timestamps.
- `open61850.supervision`: GOOSE and SV stream supervision. stNum/sqNum and
  smpCnt followed (gaps, duplicates, late messages, restarts, wraps),
  timeAllowedtoLive and SV timeouts, confRev/datSet/goID changes, simulation,
  ndsCom, smpSynch. `BusSupervisor` takes raw frames.
- `open61850-supervise`: supervision of a capture file or, on Linux, of an
  interface.

## 0.3.0

- `open61850-sv` (`python -m open61850.sv_publisher`): publishes one SV stream
  until stopped, with the options of PO's rt_sender (addresses, APPID,
  confRev, smpSynch, VLAN, three-phase waveform, periodic phase A fault) plus
  the rate, ASDUs per frame, data set layout, simulation bit, real-time
  priority, CPU and engine.

## 0.2.0

- Sampled Values publication (`open61850.sv_publisher`, re-exported by
  `open61850.sv`): streams, waveforms aligned on the UNIX epoch, periodic
  faults, 6I3U and 4I4U data sets, simulation bit, frame templates.
- `open61850-rt`: the real-time engine in Rust (`pip install "open61850[rt]"`),
  which produces the same bytes as the Python renderer; a Python thread
  engine otherwise.

## 0.1.1 (2026-09-25)

First release on PyPI; same code as 0.1.0, plus the release workflow.

## 0.1.0 (2026-09-25)

First release as a separate package; the code and its history come from the
`iec61850/` package of PO.

- MMS client: association built from `AssociationParameters` and decoded
  down to the initiate-ResponsePDU, negotiated outstanding requests honoured,
  reads, writes, GetNameList, type and data set descriptions, typed errors.
- Reports decoded from their own OptFlds and inclusion bit string.
- Report control blocks: status, free instance, reservation (edition 1 and 2
  BRCBs, URCBs), enabling with checked writes, release.
- Controls: direct and select-before-operate, normal and enhanced security.
- GOOSE and Sampled Values codecs, Ethernet/802.1Q framing, MMS data values,
  quality, SCL reader.
- Linux AF_PACKET capture for GOOSE and SV.
- `open61850-mms` command line.

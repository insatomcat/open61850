# Changelog

## 0.8.0 (2026-09-26)

- GOOSE strict decoding, for protection use: `goose.decode_goose_pdu(...,
  strict=True)`, `open61850-core`'s `decode_pdu_strict` and
  `o61850_goose_decode_frame_strict` / `_payload_strict` in the C API
  refuse what IEC 61850-8-1 forbids and the lenient decoding accepts:
  octets after the PDU, fields out of order or of another class or form,
  strings other than VisibleString129, t other than 8 octets, counters
  above 32 bits, allData missing or with another count than
  numDatSetEntries, Data of the wrong class, form or size. The lenient
  decoding stays the default.
- C API, GOOSE decoding: broken BER inside allData gives `O61850_ERR_DATA`
  (was `O61850_ERR_BER`), an empty header counter `O61850_ERR_FIELD`, a
  header Length leaving no room for a PDU `O61850_ERR_HEADER`.

## 0.7.0 (2026-09-26)

- `open61850-core`, a Rust crate in the `native/` workspace: process bus
  codecs for real-time callers (`no_std`, no allocation, no unsafe code).
  Sampled Values decoding, GOOSE encoding and decoding, MMS `Data` values
  as a flat preorder sequence. Each codec accepts what the Python codec
  accepts and writes the octets it writes: tests compare them on random and
  mutated input, and the decoders and the encoder are fuzzed.
- `libopen61850`, the C API of these codecs (`native/capi`, header
  `open61850.h`): no allocation, no state, return codes, decoded strings
  pointing into the caller's frame. Tested from C under ASan and UBSan.
  Each release carries it for x86_64 and aarch64 Linux (glibc 2.17 and
  later): header, static and shared libraries, pkg-config files.
- `goose.encode_goose_pdu` writes allData for an empty data set (`ab 00`)
  instead of leaving it out: it is not OPTIONAL in IEC 61850-8-1.
- `goose.decode_goose_pdu` refuses a timeAllowedtoLive, stNum, sqNum,
  confRev or numDatSetEntries above 64 bits (these are INT32U; leading
  zeros are still accepted).

## 0.6.0 (2026-09-25)

- The MMS server executes controls: direct and select-before-operate, normal
  and enhanced security (CommandTermination, LastApplError), selection
  timeout, Cancel, Test, time-activated operate; handlers decide what a
  command does (by default ctlVal goes to stVal). libiec61850's control
  client operates it.
- `operate(..., oper_tm=...)` and `oper_value(..., oper_tm=...)`:
  time-activated controls (an Oper with operTm).

## 0.5.0 (2026-09-25)

- `open61850.server`: an MMS server. `IedModel.from_scl` builds typed values,
  data sets and control blocks from a CID/ICD/SCD; `MmsServer` serves them
  (association, GetNameList, Identify, Read, Write, type and data set
  descriptions) and runs buffered and unbuffered reports (reservation,
  TrgOps, BufTm, integrity, GI, EntryID replay). `open61850-server` serves
  an SCL file from the command line. libiec61850's clients browse, read,
  write and receive reports from it. Controls are not executed yet.
- `open61850.mms.types.encode_type_description`; `pdu.wrap` takes the
  presentation context.

## 0.4.0 (2026-09-25)

- `open61850.pcap`: pcap and pcapng files read on any OS (as the
  `CapturedFrame` of a live capture), classic pcap written with nanosecond
  timestamps.
- `open61850.supervision`: GOOSE and SV stream supervision. stNum/sqNum and
  smpCnt followed (gaps, duplicates, late messages, restarts, wraps),
  timeAllowedtoLive and SV timeouts, confRev/datSet/goID changes, simulation,
  ndsCom, smpSynch. `BusSupervisor` takes raw frames.
- `open61850-supervise`: supervision of a capture file or, on Linux, of an
  interface.
- `open61850.mms.reference`: IEC 61850 references (`LD/LN.DO.DA [FC]`);
  every client method, `operate` and the command line take them as well as
  MMS names.
- `open61850.mms.model`: `discover` reads the server's data model (logical
  devices and nodes, data objects and attributes with their FCs, control
  blocks, data sets, optionally types); `resolve` finds a reference's FC.
- `open61850-mms browse`: the data model as a tree or one reference per line.
- Interoperability tests against libiec61850's example programs
  (`tools/interop/run.sh`, and CI).
- SV playback: `Playback` sends recorded samples instead of the waveforms,
  once or periodically, from a captured stream (`Playback.from_sv_frames`)
  or a COMTRADE record (`Playback.from_comtrade`); `open61850-sv
  --replay-pcap` and `--comtrade`. Both engines; `open61850-rt` 0.4.0.
- `open61850.goose_publisher`: GOOSE publication with the 8-1 retransmission
  scheme (min time doubling up to max time, TAL three times the wait);
  `open61850-goose` publishes from the command line. libiec61850's GOOSE
  subscriber reads it in the interoperability tests.
- `open61850.scl`: data sets and their members, GOOSE and SV control blocks
  with their GSE/SMV addresses (a `GooseControl` for the publisher), ldName,
  and the data model of the DataTypeTemplates (`load_model`).
  `open61850.mms.model.compare` and `open61850-mms compare-scl` check an IED
  against its SCL; libiec61850's examples match theirs exactly.
- `examples/`: seven runnable programs, run in CI against libiec61850.
- CI: ruff and mypy, macOS and Windows for the pure Python part.
- `open61850.comtrade`: COMTRADE records read (1991, 1999, 2013; ASCII and
  binary formats) and resampled.

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

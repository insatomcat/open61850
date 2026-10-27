# Changelog

## Unreleased

- The MMS server sends through a queue and a writer thread per
  connection. A client that stopped reading held its reports' sends,
  which ran under the model's lock: the model, the other clients'
  reports and every request waited behind it. Such a client is now
  dropped once a PDU has waited `send_timeout` seconds (10 by default)
  or its queue passes `send_queue_bytes` (16 MiB), and its blocks are
  released.
- Accepted connections use TCP keepalive and TCP_USER_TIMEOUT
  (`keepalive`, 20 s by default, None for the system's defaults): a
  client that vanished without closing (host down, cable, a Scada
  restarted elsewhere) is dropped within about that time instead of
  holding its association and its reserved report blocks for good, or
  for the 15 minutes of TCP retransmissions when reports flowed.

## 0.9.13 (2026-10-27)

- A change of the model reaches the report control blocks through an
  index of their data sets' members, made once and again when a client
  writes a DatSet: its cost is that of the attributes changed. Each change
  went through every block and each block's members, finding each
  attribute's logical device among them all, under the model's lock: on a
  relay of 14 bays (1748 blocks) whose measurements moved at each
  computation, the server took a core and answered no read.
- The COMTRADE viewer's side starts at the top beside the record's
  description and stays still as the cursor moves: the digital channels
  are named in the digital panel, the R-X diagram shrinks to hold in its
  box; clear() makes the canvases again; the zones choice is hidden
  when there is no zone.

## 0.9.12 (2026-10-26)

- The COMTRADE viewer draws the six impedance loops on an R-X diagram,
  as a distance protection computes them, under the readout: on the
  settings the page gives (`show(..., {settings})`, `settings()`,
  `settingsFor(stream)`; `lineSettings(r1, x1, r0, x0)` for a line's
  k0 and Z1), a relay's zones included. It was open61850-protection's
  own, beside the viewer. Without zones, the diagram is framed on the
  line.
- The channels are named without their stream's name, which the
  selector says; the digital channels drawn by default are those that
  change (a position on all along was a line of its own); the readout's
  digital channels wrap instead of widening the side panel; the grid
  falls back on the page's `--line`, the loops on colours of their own.

## 0.9.11 (2026-10-26)

- `comtrade.viewer_script()`: a COMTRADE viewer for a browser page
  (`comtrade_viewer.js`, shipped in the package), which a server puts in
  its page. It reads a record as `load_comtrade` does (the four formats,
  the three revisions; a test runs it in node and compares), from its
  files or a zip of them, and draws it: the currents, the voltages and
  the other analog channels, the digital channels that are on or
  change, a cursor with each channel's value, RMS and angle over the
  cycle, a zoom. A file of several streams (each channel's ccbm, a
  merging unit's svID) shows one at a time. It was open61850-protection's
  records analyser; simu-scope uses it too.

## 0.9.10 (2026-10-14)

- The MMS server keeps a buffered block's entries encoded, made once when
  the entry is: one object per entry for the garbage collector, whatever
  the data set. An entry kept its values as decoded data, about twenty
  objects each, so that a relay of 118 logical devices whose blocks two
  clients had enabled held 18 million objects and 2 GB in its buffers,
  and each full collection stopped every thread of the server for
  seconds (5 s measured), long enough for a client's request to time
  out. On that model, the process takes 270 MB instead of 2.1 GB, and a
  full collection 70 ms instead of 850 ms on a developer's machine.
- A block's buffer is also bounded in bytes of encoded values and
  reasons: `MmsServer(report_buffer_bytes=...)`, 256 KiB by default
  (`reporting.BUFFER_BYTES`), besides the 1000 entries. The oldest
  entries go first, the newest always stays, and `BufOvfl` says when one
  never sent was dropped.
- `protocol.information_report` takes access results already encoded
  (`encoded`), and `protocol.access_results` encodes them.

## 0.9.9 (2026-10-13)

- `operate` writes Cancel when an object it selected (SBO or SBOw) does
  not accept the Oper that follows, refused or unanswered. The selection
  stayed held until the server's `sboTimeout` (30 s by default), and
  every other command on the object, from any client, got
  `object-already-selected` in the meantime.
- `operate` gives each command the next ctlNum of a counter shared by the
  process (`next_ctl_num`) when the call gives none. It sent 0 for every
  command, so that a server's log and its LastApplError could not tell
  one command from the next. `cancel_value` builds the Cancel structure.

## 0.9.8 (2026-10-11)

- The MMS server ends the reservation it keeps for a buffered block's
  client that left: after `ResvTms` seconds, `ResvTms` goes back to 0
  (and `Owner` to none). It stayed at its value, so that a client looking
  for a free instance (`rcb.find_free`) found the block reserved for
  ever, and a client that associated again a few times found none left.

## 0.9.7 (2026-10-11)

- `MmsServer.stop()` no longer leaves its accept thread ending on an
  AttributeError when a client connected as the server stopped.
- The MMS server's buffered reports say `BufOvfl` only when the full
  buffer dropped an entry no client had been sent. Once a block had made
  1000 entries, every report to its enabled client said TRUE, though the
  entry dropped had been sent.

## 0.9.6 (2026-10-09)

- `IedModel.batch()`: the changes a thread makes inside reach the
  listeners together at its end, so a data object written attribute by
  attribute, or several written at the same instant, make one report
  entry instead of one per attribute (a server application writing a
  status's `general`, then its phases, sent a report for each).
- Controls show IEC 61850-7-3 edition 2.1's `opRcvd`, `opOk` and `tOpOk`
  (FC OR) when the object's type has them: `opRcvd` TRUE from an
  accepted Oper, `opOk` TRUE with `tOpOk` once the handler has given the
  order (done, or in execution), both FALSE again when the command ends
  (`finish` for one in execution). A test command is received, never
  given.

## 0.9.5 (2026-10-09)

- The MMS server's controls: `ControlEngine.set_check` runs a check
  before the response to SBOw and Oper, in every control model, and
  refuses with its AddCause (libiec61850's check handler): an
  interlocking or authority refusal now reaches an enhanced security
  client at Oper instead of in a negative CommandTermination. A handler
  may return `IN_EXECUTION` for a command whose end comes later (a
  switch reaching its position): the object refuses other commands
  (command-already-in-execution) until the application calls
  `ControlEngine.finish(reference, cause)`, which sends the
  CommandTermination, negative with an AddCause such as
  time-limit-over. `ControlEngine.executing` tells whether a command is
  in execution, and `ADD_CAUSE_*` names the causes of IEC 61850-7-2.

## 0.9.4 (2026-10-04)

- The MMS server has setting groups (IEC 61850-7-2 clause 16): a
  logical device whose LLN0 has a `SettingControl` gets its SGCB
  (`LLN0$SP$SGCB`, libiec61850's layout) and `IedModel.setting_groups`,
  each group's values from the SCL's `Val sGroup`. `SettingGroupEngine`
  (`MmsServer.setting_groups`) serves SelectActiveSG, SelectEditSG with
  its reservation (ResvTms, the client's going) and ConfirmEditSGValues
  as libiec61850 does; the application follows or refuses them with
  `on_active`, `on_edit`, `on_confirm`, and changes the groups with
  `select_active` and `set_values`. Checked against libiec61850's
  `server_example_sg` in the interoperability tests.
- `open61850.mms`: `read_sgcb`, `select_active_sg`, `select_edit_sg`,
  `confirm_edit_sg_values` for the client.
- An SCL attribute in FC SE has its SG twin, in the server's model and in
  `scl.load_model`, as libiec61850 builds it; `discover` and `compare`
  count the SGCB as a control block.

## 0.9.3 (2026-09-28)

- `comtrade.save_comtrade` writes a `Comtrade` record in revision 1999 or
  2013, in any of the four data formats (a disturbance recorder's
  output). The reader keeps the 2013 time code and time quality lines
  (`time_code`, `local_code`, `tmq_code`, `leap_second`).

## 0.9.2 (2026-09-28)

- `PacketCapture.ring()` and `next_slot` open the low-latency capture's
  TPACKET_V2 ring to a reader of its own: a loop in C that takes each
  frame without a Python object, `recv()` resuming where it stopped. The
  module's notes give the slot protocol.

## 0.9.1 (2026-09-28)

- `PacketCapture(..., busy_poll=0)` turns the host's busy polling off for
  the capture's socket (`SO_BUSY_POLL`), and `busy_poll` reads it back.
  The tuned profiles `network-latency` and `realtime` set
  `net.core.busy_poll` and `busy_read` to 50 us, which an AF_PACKET socket
  cannot use: a protection on a SEAPATH hypervisor spent 57.8 us of system
  time per SV frame spinning in poll(), 6.6 without, for the same latency.

## 0.9.0 (2026-09-26)

- `GoosePublisher.publish(values, send_now=True)`: the caller sends the
  first message of the new state before returning, and the publisher's
  thread only repeats it. A protection trips from the thread that decided,
  without waiting for another thread to be scheduled.
- `PacketCapture(..., low_latency=True)` reads a TPACKET_V2 ring: each
  frame reaches Python as soon as the kernel wrote it, where a TPACKET_V3
  block waits for a timer counted in kernel ticks (8.4 ms in the median,
  up to 16 ms, on a process bus host). For a protection acting on each
  sample; the default stays the block ring.

## 0.8.1 (2026-09-26)

- The READMEs published on PyPI (open61850, open61850-rt) link to GitHub
  with absolute URLs; their relative links led nowhere there.

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

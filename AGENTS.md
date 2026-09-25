# open61850: maintainer notes

IEC 61850 in pure Python (Apache 2.0), standard library only, Python 3.10+.
It grew inside PO, a test and diagnostic platform for a digital substation
process bus, as `iec61850/`, and moved to its own repository at 0.1.0 with
its history. PO is its first user. Scope so far: the client side, kept
simple. Tested against a Schneider VMC7 and an ABB SSC600.

Everything is in English. No em-dash in code, comments, commits or docs.
Commit messages in English with the DCO `Signed-off-by` trailer.

## Layout

`src/open61850/` (src layout), tests in `tests/` (they add `src` to the path
through `conftest.py`, no install needed), `tools/bench_sv_decode.py`.

| Module | Content |
|--------|---------|
| `ber.py` | X.690 primitives: tags as the int of their identifier octets (`0x83`, `0xBF48`), definite lengths, minimal INTEGER, lenient unsigned decode, OBJECT IDENTIFIER, `iter_tlvs`, `expect_tlv`, `BerError`. `decode_tlv` has fast paths for short tags and lengths. |
| `data.py` | MMS `Data` CHOICE (`BoolData` ... `RawData`), `encode_data` / `decode_data*`, UtcTime and binary-time helpers. `TimestampData.quality` keeps the TimeQuality octet, `FloatData.double` the width; float32 decodes to its shortest decimal. Unsigned values get a leading `00` when the high bit is set. |
| `display.py` | Readable text of values (positions, octet strings). |
| `ethernet.py` | Ethernet II / 802.1Q + APPID header: `parse_frame`, `build_frame`, `EthernetFrame`. |
| `goose.py` | `GoosePDU` (with `time_quality`), PDU and frame codec, `GooseDecodeError` on missing mandatory fields and on header counters above 64 bits (INT32U, read leniently). |
| `sv.py` | `SvPDU` / `SvAsdu` with every 9-2 / 61869-9 field (datSet, refrTm, smpRate, smpMod, gmIdentity), PDU and frame codec, INT32+quality sample helpers. `_asdu_fields` has a fast path (22 us per 2-ASDU frame on a Xeon Gold server, 9 us on a recent Mac: `tools/bench_sv_decode.py`). |
| `quality.py` | `Quality` (7-3, 13-bit bit string) and `TimeQuality` (UtcTime octet) in readable form. |
| `scl.py` | SCL reader: IEDs, ConnectedAP addresses, LDevice instances (ldName honoured), ReportControl blocks with their data sets and instance counts, DataSets with FCDA members as `Reference`s, GSEControl / SampledValueControl with their GSE / SMV addresses (APPID and VLAN-ID hexadecimal, MinTime/MaxTime), `GooseControlBlock.goose_control()` for the publisher. `load_model` / `ied_model` build a `ServerModel` from the DataTypeTemplates (DO, SDO, DA, BDA; arrays are leaves; indexed RCBs get their instances); `mms.model.compare` lists the differences. |
| `pcap.py` | pcap (micro and nanosecond, both byte orders) and pcapng (sections, `if_tsresol`, `if_tsoffset`, EPB direction flag, SPB, obsolete PB) read as `CapturedFrame`; Ethernet only. `PcapWriter`: classic pcap, nanoseconds. Checked against editcap 4.0.17 output (`tests/data/editcap_pcapng.json`), and tshark reads what the writer produces. |
| `supervision.py` | `GooseSupervisor` / `SvSupervisor`: state only, fed with decoded messages and a time, return `Event`s (`EventKind`); `check(now)` for timeouts. `BusSupervisor` takes raw frames and counts malformed ones; `open61850-supervise` runs it on files or live. See below. |
| `capture.py` | Linux capture without libpcap: `PacketCapture` reads an AF_PACKET TPACKET_V3 ring (mmap, one poll per block), classic BPF on ethertypes that works with or without a stripped tag, 802.1Q tag put back from the ring header, kernel timestamps, promiscuous membership, `PACKET_STATISTICS` drops. |
| `mms/transport.py` | TPKT + COTP class 0: `IsoConnection` (CR/CC, segmentation on send, EOT reassembly on receive, DR = closed). |
| `mms/association.py` | Association request built from `AssociationParameters` (Session CONNECT, Presentation CP-type, ACSE AARQ, MMS initiate-RequestPDU) and `decode_association_response` (ACCEPT/CPA/AARE/initiate-ResponsePDU to an `Association`; refusal at any layer raises `AssociationError`). The defaults give the 180 bytes PO replayed from a capture before the encoder existed; a test pins them. |
| `mms/pdu.py` | Session/presentation envelope (`wrap`/`unwrap`), `ObjectName`, Read / Write / GetNameList / GetVariableAccessAttributes / GetNamedVariableListAttributes requests and responses, confirmed-Error, Reject, informationReport. Requests match IEDscout captures. |
| `mms/client.py` | `MmsClient`: one receive thread, responses matched by invokeID (several requests in flight, from any thread, up to the negotiated `max_outstanding_calling`), informationReports to a callback and to listeners on the receive thread, typed errors (`DataAccessError`, `ServiceError`, `MmsReject`, `MmsTimeout`, `MmsConnectionError`). |
| `mms/report.py` | Report decoding driven by the report's own OptFlds and inclusion bit string (data references, ConfRev, segmentation, reason codes); `OptFlds` / `TrgOps` / `ReasonCode` flag classes. |
| `mms/reference.py` | `Reference` (ld, ln, path, fc): `LD/LN.DO.DA [FC]` <-> `LN$FC$DO$DA` in domain LD, `parse` takes both notations (`[FC]` suffix or `fc=`), `to_object_name` (MMS text goes through untouched), `data_set_object_name` (`LD/LLN0.DS1` -> `LLN0$DS1`). |
| `mms/model.py` | `discover`: GetNameList of variables and variable lists per domain (plus GetVariableAccessAttributes per LN with `types=True`) into `ServerModel` / `LogicalDevice` / `LogicalNode`; leaves, data objects, control blocks (FC BR RP LG GO GS MS US), data sets, `type_of`, `resolve` (finds the FC, refuses an ambiguous one). |
| `mms/types.py` | GetVariableAccessAttributes type descriptions (`StructureType`, `ArrayType`, `PrimitiveType`) and `label()`, which names every leaf of a value after its type (`cVal.mag.f`). |
| `mms/rcb.py` | RCB status (RptEna, Resv/ResvTms, Owner, RptID, DatSet), `usable` / `find_free` among instances (`group_instances` strips the trailing number): free ones first, then the ones our own address reserved without enabling; `enable` reserves a BRCB with ResvTms first (the VMC7 refuses configuration writes otherwise; edition 1 BRCBs have no ResvTms), then typed, checked writes; `disable` also releases (ResvTms = 0 or Resv = FALSE). |
| `mms/control.py` | `operate()`: ctlModel read from `CF`, then Oper (direct), SBO read + Oper, or SBOw + Oper; enhanced security waits for the CommandTermination. Refusals raise `ControlError` with the `LastApplError` (AddCause names per 7-2 Ed2). `Origin` defaults to station-control (orCat 2). Report listeners carry the LastApplError / termination to the waiting call. |
| `mms/__main__.py` | The `open61850-mms` command line. |
| `goose_publisher.py` | `GooseControl` (identity, addresses, min/max time, TAL factor), `GoosePublisher`: a thread waits on a condition; `publish` makes a new state (stNum + 1, sqNum 0, t = now) sent at once, then waits min, 2 min... max, max on a schedule that does not drift; TAL = 3 x the wait, like libiec61850 (`mms_goose.c`). `send` can replace the socket (tests). `open61850-goose` reads new states on stdin. |
| `comtrade.py` | COMTRADE reader (C37.111 1991/1999/2013, ASCII, BINARY, BINARY32, FLOAT32; `.cff` not read): `analog()` in primary or secondary values (the `ps` field and the ratio), missing samples NaN (99999, empty, 0x8000, 0x80000000, NaN), `times()` from the rates or the timestamps, `resample` (linear, NaN as 0). Checked against the `comtrade` package from PyPI on the four formats: same values within float32 rounding, same digital states and times. |
| `server/model.py` | `IedModel` from SCL: a `Node` tree per LN (FC, DO, SDO, DA, BDA), bType to MMS type with libiec61850's sizes (Quality `bit-string(<=13)`, Enum `integer8`, Check `bit-string(<=2)`...), `Val` and DOI/DAI initial values (Enum names through EnumType), control blocks as 8-1 structures (BRCB, URCB, GoCB, MSVCB), FCs in libiec61850's order (MX ST CO CF DC SP SG RP LG BR GO SV SE MS US EX SR OR BL). Edition 1 files spell `TimeofEntry` and have no BRCB ResvTms; `gi` and `bufOvfl` default to true. `set` (application, any FC) and `write` (client: CF DC SP SV SE BL) with type checks; change listeners. |
| `server/protocol.py` | Server side of COTP (CR/CC), association (CONNECT/CP/AARQ/initiate-Request decoded; ACCEPT/CPA/AARE/initiate-Response laid out like the VMC7's, with the client's presentation contexts), MMS requests and responses, errors, rejects, informationReport. |
| `server/server.py` | `MmsServer`: accept thread, one thread per client; GetNameList (sorted by string, continueAfter, pages within the PDU size), Identify, Read (variables or a data set), Write (through `write_hooks` first), GetVariableAccessAttributes, GetNamedVariableListAttributes, Conclude; Reject otherwise. `stop()` shuts the listening socket down first (Linux leaves accept() blocked and the port bound on close alone). |
| `server/reporting.py` | `ReportEngine`, attached by `MmsServer.start`: RCB writes through a write hook (Resv / ResvTms + Owner reservation, temporarily-unavailable when held by another client, configuration frozen while enabled, GI then back to FALSE, PurgeBuf), model changes to entries when a data set member covers the changed leaf and TrgOps asks for the leaf's SCL trigger (dchg/qchg/dupd), values captured at the change, BufTm gathering (a member changing again flushes first), IntgPd, a BRCB buffer (1000 entries, EntryID, BufOvfl) replayed after EntryID on enabling. URCB reports go out with the OptFlds bits bufOvfl and entryID cleared, as libiec61850 does (their fields are absent). On disconnection blocks are disabled; a BRCB stays reserved for its address ResvTms seconds. One scheduler thread. |
| `server/control.py` | `ControlEngine`, attached by `MmsServer.start`: ctlModel from `CF$DO$ctlModel`; read of SBO selects (sbo-normal; the reference, or "" when refused), SBOw selects (sbo-enhanced), Cancel releases; a selection is its client's and lapses after `CF$DO$sboTimeout` (30 s default). Oper executes through a handler (None = done, int = AddCause); the default copies ctlVal to `ST$DO$stVal` (Dbpos from a boolean) and stamps t, origin, ctlNum. Refusals: LastApplError informationReport, then object-access-denied. Enhanced security: positive write response, then (through `ServerConnection.after_response`) execution and the CommandTermination, negative with LastApplError. operTm in the future: accepted, executed at that time. Test: checked, not executed. |
| `server/__main__.py` | `open61850-server`: serves an SCL file's IED; `REFERENCE VALUE` lines on stdin set values (booleans, numbers, Dbpos names, text). Stdin closing does not stop it. |
| `sv_publisher.py` | SV publication. `Wave` (value = offset + amplitude sin(2 pi f t + phase), times scale, rounded half to even), `Fault` (periodic, aligned on the UNIX epoch, same schedule as PO's rt_sender), `SvStream`, `three_phase` (6I3U / 4I4U, phase A overridable), `build_template` (a frame encoded once, offsets of smpCnt and samples found by walking the TLVs), `render_frame` (the reference renderer), `Publisher` (native engine, or a Python thread). `Playback`: INT32 rows (and optional qualities) sent instead of the waves and fault from sample `start_second * rate + start_smp`, optionally every `repeat_s`; `start_second=None` is set by `Publisher.start`; `from_sv_frames` (captured stream, recent smpCnt skipped), `from_comtrade` (resampled). |

Public API: each module's `__all__` (the `mms` package re-exports the usual
names). Only `mms`, `capture` and the SV `Publisher` do network I/O, and
`pcap` reads and writes files; the library configures no logging and
imports nothing outside the standard library (a test checks it).

## MMS on the wire

Every confirmed request after the association is built as:

```
01 00 01 00                 Session: Give-Tokens + Data-Transfer SPDUs (fixed)
61 L  30 L                  Presentation: fully-encoded-data, PDV-list
      02 01 03              presentation-context-identifier = 3 (MMS context)
      a0 L                  single-ASN1-type
         a0 L               MMS confirmed-RequestPDU
            02 02 xx xx     invokeID
            a4|a5|a1 ...    read | write | getNameList
```

Only the association uses the full Session, Presentation and ACSE layers.
Answers to the default request (`tests/data/association_responses.json`): a
VMC7 accepts 5 outstanding requests and nesting level 7, an ABB SSC600 only 1
outstanding request and nesting level 5, so a client that pipelines must
honour the negotiated value.

GetNameList follows ISO 9506 and matches IEDscout byte for byte:
`a1 { a0 { 80 01 <class> } a1 { 80 00 | 81 <domain> } [82 <continueAfter>] }`.
Names come in pages followed with continueAfter (the VMC7 answers 100 names
per page); only `<LN>$BR|RP$<name>` are blocks. Responses above ~1 KB arrive
in several COTP DT segments, joined until the EOT bit.

What IEDscout captures on a VMC7 taught (fixtures in `tests/data/iedscout_*.json`):
- IEDscout pipelines requests, so responses must be matched by invokeID.
- A confirmed-ErrorPDU carries its invokeID as `80 ..` ([0] IMPLICIT), where
  requests and responses use `02 ..`.
- IEDscout's own Initiate is 204 bytes, ours 180; both are accepted.
- IEDscout enables a BRCB with RptEna=FALSE, a read of the whole block,
  ResvTms=42, RptEna=TRUE: it keeps the IED's TrgOps/OptFlds and does not
  purge, so ~500 buffered reports arrive at once.
- Data-change reports include 1 to 3 of 19 members: partial inclusion is the
  normal case once dchg/qchg are enabled.
- Control is direct-with-enhanced-security: one Oper write per command
  (ctlVal TRUE = close, FALSE = open, orCat 2, Check c0), write response in
  ~2 ms, then a CommandTermination (informationReport on `...$CO$Pos$Oper`
  echoing the Oper) 60 to 90 ms later. Checked with `operate()` on a
  simulated breaker: open then close, termination after 65 and 86 ms.
- BOOLEAN TRUE goes out as `ff` (DER) where IEDscout sends `01`; the VMC7
  accepts both.

VMC7 reservations: a BRCB reserved with ResvTms = 5 stays reserved, with
Owner = the client IP, as long as any association from that IP is alive. A
client that restarts and reconnects within a second therefore leaks its
instances unless it releases them (`rcb.disable`) or reclaims its own
(`usable(..., reclaim_own=True)`).

`rcb.enable` writes in this order, each write checked: ResvTms, IntgPd,
TrgOps, OptFlds, PurgeBuf, EntryID=0, RptEna, then GI.

## Interoperability with libiec61850

`tools/interop/run.sh` builds libiec61850 (tag pinned in
`tools/interop/Dockerfile`) and runs `tests/test_interop_libiec61850.py`
in a privileged container; CI does the same. It checks, against
`server_example_basic_io`, `server_example_control`,
`server_example_goose` and `sv_publisher_example`: association, model
discovery with types, reads in both notations, data set members, a
buffered report control block enabled then released, direct and SBO
controls with normal and enhanced security (and a refused one with its
LastApplError), GOOSE (two GoCBs, supervised without anomaly), SV, and
libiec61850's GOOSE subscriber reading our GoosePublisher (every message
valid, values and TAL as sent). On `lo` each frame arrives twice and
libiec61850 flags the second copy (same sqNum) INVALID. The model built
from each example's CID matches the one its server exposes, with no
difference (106 attributes for basic_io), and the GSE/SMV addresses of the
CIDs are those the publishers send (APPID `1000` in SCL is 0x1000). What
the examples taught: libiec61850 lists names in an order of its own (the
same set as ours, which sorts by string), and its GOOSE example updates
its values every second.

The server, loaded with basic_io's CID, is read by libiec61850's
`mms_utility` (identify, domains), browsed by `iec61850_client_example2`,
and read, written and asked for its data set and RCB by
`iec61850_client_example1`. Built from the same CIDs, its model has the
names, types and initial values of libiec61850's servers, checked
attribute by attribute (the differences are runtime values). libiec61850's
`client_example1` and `client_example_reporting` enable URCBs on it and
receive its GI, data change and integrity reports; `client_example_control`
operates its four control models (terminations positive, and negative with
AddCause 10 from a refusing handler). The open61850 client's `oper_tm`
operates libiec61850's time-activated objects (SPCSO5 to 8).

## The native SV engine (`native/`)

Rust crate `open61850-rt` built with maturin (PyO3, abi3 for Python 3.10+),
published as the `open61850-rt` distribution; `open61850[rt]` pulls it on
Linux. Python passes the templates, offsets and waveform parameters
(`sv_publisher._native_streams`); the engine renders into one buffer per
stream before each deadline, sleeps with `clock_nanosleep(CLOCK_REALTIME,
TIMER_ABSTIME)` until the time of the frame's first sample, and sends all
streams with one `sendmmsg`. Deadlines are computed from the second (no
accumulated rounding). Priority (`SCHED_FIFO`) and CPU pinning are applied
to the engine thread before it reports ready, so a refusal raises at
`start()`.

A playback reaches the engine as native-endian 32-bit arrays (values,
optional qualities), its channel count, its first absolute sample number
and its period in samples; row = (second * rate + smpCnt - start) mod
period, taken only inside the recording, as `Playback.index` does. Engine
0.4 added it: `Publisher` refuses a playback with an older engine, which
would ignore it.

The sample maths mirrors `Wave.value` operation for operation: phase from
`fmod(f * second, 1) + f * smpCnt / rate` (keeps precision at large UNIX
times), `2 pi * cycles + to_radians(phase)`, libm `sin`, `round_ties_even`
like Python's `round`. `tests/test_sv_native.py` compares the bytes of both
renderers on random streams; keep them identical when changing either.

Measured on a Xeon Gold server (loopback, 10 s, 3 streams at 4800
samples/s): no priority, median 62 µs after the nominal time, p99 73 µs,
max 0.9 ms; `SCHED_FIFO` 50, median 6 µs, p99 14 µs, max 46 µs. PO's C
rt_sender at the same priority (1 stream): median 4 µs, p99 11 µs, max 38 µs.

`native/` is a Cargo workspace: the engine at its root, `core/` and `capi/`
beside it (`fuzz/` is excluded, it builds on nightly). `open61850-core`
holds process bus codecs for real-time callers (a protection runtime in C
is the target): `no_std`, no unsafe code, no allocation, decoding borrows
from the input.
Each module mirrors the Python module of the same name: it accepts exactly
what the Python decoder accepts and writes the octets the Python encoder
writes. `ber` (tags as the int of their identifier octets, lenient
unsigned; `Writer` into a caller's buffer, minimal lengths and INTEGERs),
`ethernet` (`parse_header` starts after the EtherType, `parse_frame` at the
MAC; `Address` writes the header), `time` (UtcTime), `sv` (`decode_pdu`
checks every ASDU and noASDU, then `asdus()` walks them again;
`decode_payload` and `decode_frame`; `int32_samples`), `data` (MMS `Data`
as a flat preorder sequence: `Structure(n)` and `Array(n)` are followed by
their members; written with `sequence_len` then `write_sequence`, nesting
at most 32 deep; read with `check_sequence`, which checks every structure
at any depth without recursion or stack (each structure's members tile it,
then one pass walks the values in preorder), then `iter_sequence`; an
INTEGER beyond 64 bits reads as `Raw`), `goose` (`encode_pdu`,
`encode_frame`: lengths measured first, then written once into the buffer;
`BufferTooSmall` says how many octets are needed; stNum, sqNum, t and
retransmission stay with the caller. `decode_pdu`, `decode_payload`,
`decode_frame` return a `Received`: header fields found by tag number
whatever their class and form, last occurrence winning, counters up to 64
bits, allData checked, `values()` to read it). The engine exposes
`decode_sv_pdu`, `decode_sv_frame`, `encode_goose_pdu`,
`encode_goose_frame`, `decode_goose_pdu` and `decode_goose_frame` to Python
for the tests.
`tests/test_sv_decode_native.py` compares the SV decoder with
`open61850.sv` on random PDUs and frames, BER forms the encoder never
writes (long and non-minimal lengths, high tags, unknown, repeated and
shuffled fields) and byte mutations of each: same refusals, same fields.
`tests/test_goose_encode_native.py` compares the GOOSE encoder with
`open61850.goose` on random messages (every Data type, nesting, INTEGER
and length boundaries, non-ASCII VisibleStrings): same octets, same
refusals. `tests/test_goose_decode_native.py` compares the GOOSE decoder
with `open61850.goose` on encoded messages, PDUs written TLV by TLV in
forms the encoder never uses (fields of any class, padded high tag numbers,
repeated and shuffled fields, counters with leading zeros or above 64
bits, IA5 strings, floats and times of other sizes, INTEGERs beyond 64
bits, 10 to 80 nested structures) and byte mutations: same refusals, same
values. Docker on the dev Mac (`cargo run --release -p open61850-core
--example ...`): the 2-ASDU frame of `tools/bench_sv_decode.py` decodes,
samples read, in about 105 ns (`bench_sv_decode`); a 168-byte trip GOOSE
of 10 entries encodes in about 130 ns and decodes, values read, in about
100 ns (`bench_goose`).

The encoder reads allData through the `DataList` trait (a slice, an
array, or the C API's array read in place); `measure` returns tags and
lengths only: returning the whole `Data` through the recursion cost 40 %
on the trip frame.

`open61850-c` (`native/capi`) is the C API: `staticlib` and `cdylib`
`libopen61850`, header `include/open61850.h` generated by cbindgen 0.29.4
and committed (`tests/run.sh` fails when it is stale). `o61850_*`
functions return 0 or a negative `O61850_ERR_*`, allocate nothing, keep
no state; decoded `o61850_bytes` point into the caller's frame; a too
small output gives `O61850_ERR_BUFFER` with the size needed; a refused
frame still reports its MACs and VLAN (own-echo filtering); a panic is
caught as `O61850_ERR_INTERNAL`. allData values are `o61850_data` (kind +
union) in preorder, read in place by the encoder. `tests/run.sh` builds
`tests/test_capi.c` with ASan and UBSan: frames written by the Python
codecs, every return code, 200,000 mutations through every decoder; it
compiles the header as C++ too. `native/fuzz` (cargo-fuzz): `sv_decode`
and `goose_decode` (no panic, counts consistent), `goose_roundtrip` (a
frame the encoder writes decodes to the same fields and values, floats by
their bits); CI runs each for a minute. A first local minute each: 38.6 M,
15.8 M and 1.8 M runs, nothing found; a BinaryTime written backwards was
found in seconds.

Building locally without Rust installed: Docker (`rust:1-slim-bookworm`
plus `maturin`), or `quay.io/pypa/manylinux2014_x86_64` for an x86_64 wheel.

## Capture

Linux only (AF_PACKET), root or `CAP_NET_RAW`. It replaced pcapy in PO after
a side-by-side check on a real process bus, 10 s: the same 152,633 frames
byte for byte (tags included), timestamps within 1.2 us, no drops; CPU
2.1 us/frame against 1.4 us for pcapy. A first version with one `recvmsg`
per frame cost 30 us/frame: keep the ring. With libpcap, the `vlan` keyword
shifted the offsets of every later test (across `or` too) and let only the
host's own SV streams through on a NIC that strips tags; `ethertype_filter`
checks both positions instead. On `lo` every frame shows up twice
(`PACKET_OUTGOING`): pass `outgoing=False`.

## Supervision

The ideas come from a private GOOSE/SV package of a protection project,
shared by its maintainer, and are rewritten here. Its subscribers dropped
every frame whose stNum was below the last one seen: a restarted IED was
ignored until its stNum passed the old value. Here a counter behind the reference is a duplicate if
it is among the last 16 accepted, late otherwise (and comes off the missed
count); further behind, a restart that becomes the new reference.

smpCnt wraps once per second. The wrap comes from `sample_rate`, from smpRate
when smpMod = 1 (samples per second), or from the highest count seen before
the first wrap. Distances are taken modulo the wrap: half a second or more
ahead is a restart, because a loss count would mean nothing. With 2 ASDUs per
frame, a duplicated frame gives two DUPLICATE events (one per ASDU).

On a 10 s synthetic capture (24,000 frames, 4800 samples/s, 2 ASDUs), reading
the file, decoding and supervising take 12 us per frame on a recent Mac.
Checked live in Docker: `open61850-sv` on `lo` for 3 s, 7,208 frames, all
supervised, none missed.

## Tests

`python -m pytest`. `ruff check src tests tools examples` and `mypy` (configured in
`pyproject.toml`, versions pinned in CI) must pass: typed accessors over
`# type: ignore`, and `Optional[...]` as the code writes it. Golden bytes come from IED captures (IEDscout), round
trips, and a fake IED on a socketpair for the client. The AF_PACKET tests
need Linux and root (`sudo python -m pytest tests/test_capture.py`; CI does
it). Golden bytes changing means the wire format changed: check it against
a capture before updating them. Captures stay out of git; only the few
bytes a test needs go to `tests/data/`.

No infrastructure details in git: no host names, lab addresses, IED
instance names or stream names of a real site. Use `IED01_...` and
`192.0.2.x` (RFC 5737).

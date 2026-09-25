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
| `goose.py` | `GoosePDU` (with `time_quality`), PDU and frame codec, `GooseDecodeError` on missing mandatory fields. |
| `sv.py` | `SvPDU` / `SvAsdu` with every 9-2 / 61869-9 field (datSet, refrTm, smpRate, smpMod, gmIdentity), PDU and frame codec, INT32+quality sample helpers. `_asdu_fields` has a fast path (22 us per 2-ASDU frame on a Xeon Gold server, 9 us on a recent Mac: `tools/bench_sv_decode.py`). |
| `quality.py` | `Quality` (7-3, 13-bit bit string) and `TimeQuality` (UtcTime octet) in readable form. |
| `scl.py` | SCL reader: IEDs, ConnectedAP addresses, LDevice instances, ReportControl blocks with their data sets and instance counts. |
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
libiec61850 flags the second copy (same sqNum) INVALID. What
the examples taught: libiec61850 lists names in alphabetical order (FC CF
before ST), and its GOOSE example updates its values every second.

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

`python -m pytest`. Golden bytes come from IED captures (IEDscout), round
trips, and a fake IED on a socketpair for the client. The AF_PACKET tests
need Linux and root (`sudo python -m pytest tests/test_capture.py`; CI does
it). Golden bytes changing means the wire format changed: check it against
a capture before updating them. Captures stay out of git; only the few
bytes a test needs go to `tests/data/`.

No infrastructure details in git: no host names, lab addresses, IED
instance names or stream names of a real site. Use `IED01_...` and
`192.0.2.x` (RFC 5737).

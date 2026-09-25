# Contributing to open61850

Bug reports, captures of IEDs we have not seen, and pull requests are welcome. Reports about a device are the most useful when they say its make, model and firmware, and include the bytes that surprised you (a pcap, or the hex of the PDU).

## Development

```bash
python -m pip install pytest ruff==0.16.9 mypy==2.3.1
python -m pytest                       # no network needed
ruff check src tests tools examples
mypy
```

The library uses the standard library only (Python 3.10 or later); a test checks it. The native engine in `native/` is Rust (PyO3, maturin): `pip install ./native` builds it, and `tests/test_sv_native.py` compares its bytes with the Python renderer.

Tests that need Linux and root (AF_PACKET capture and publication) skip themselves elsewhere; `sudo python -m pytest` runs them, or `docker run --rm --privileged -v "$PWD":/src -w /src python:3.13-slim sh -c "pip install pytest && python -m pytest"`.

`tools/interop/run.sh` runs the interoperability tests against libiec61850's example servers, publishers and subscriber in Docker. CI runs everything above on every push.

## Rules of the house

- Golden bytes in the tests come from real devices or from other implementations. When they change, the wire format changed: check it against a capture first.
- Captures stay out of git. Only the few bytes a test needs go to `tests/data/`, as hex in JSON, with where they come from.
- No infrastructure details in git: no host names, lab addresses, IED or stream names of a real site. Use `IED01_...`, `192.0.2.x` (RFC 5737) and locally administered MAC addresses (`02:...`).
- English everywhere, in code, comments, commits and documentation.
- Commits carry a `Signed-off-by:` line (Developer Certificate of Origin, `git commit -s`).

`AGENTS.md` holds the maintainer notes: what the IED captures taught, and why the code does what it does.

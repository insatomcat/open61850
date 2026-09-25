# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""IEC 61850 in pure Python (Apache-2.0), standard library only.

Codecs, with no I/O:

- :mod:`open61850.ber`: BER (X.690) primitives.
- :mod:`open61850.data`: the MMS ``Data`` values shared by MMS, GOOSE and reports.
- :mod:`open61850.quality`: Quality and TimeQuality in readable form.
- :mod:`open61850.display`: readable text for MMS values.
- :mod:`open61850.ethernet`: Ethernet II / 802.1Q framing for GOOSE and SV.
- :mod:`open61850.goose`: GOOSE PDUs and frames (IEC 61850-8-1).
- :mod:`open61850.sv`: Sampled Values PDUs and frames (IEC 61850-9-2, IEC 61869-9).
- :mod:`open61850.scl`: SCL files (IEDs, logical devices, data sets, report control blocks).
- :mod:`open61850.comtrade`: COMTRADE records (IEEE C37.111), read and resampled.
- :mod:`open61850.supervision`: GOOSE and SV stream supervision (counters,
  timeAllowedtoLive, configuration), fed with decoded messages.

With I/O:

- :mod:`open61850.mms`: MMS client over TCP (association, reads, writes,
  reports, report control blocks, controls).
- :mod:`open61850.capture`: GOOSE and SV capture on Linux (AF_PACKET ring).
- :mod:`open61850.pcap`: pcap and pcapng files, read and written.
- :mod:`open61850.goose_publisher`: GOOSE publication with the 8-1 retransmission scheme.
- :mod:`open61850.sv_publisher`: Sampled Values publication (streams, waveforms,
  faults); real-time sending with the ``open61850-rt`` engine (``open61850[rt]``).

The names listed in each module's ``__all__`` (or, for :mod:`open61850.mms`,
exported by the package) are the public API; anything with a leading
underscore is internal. Until 1.0, minor versions may change the API.
"""

__version__ = "0.3.0"

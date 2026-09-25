# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Act as a merging unit: 9-2LE / 61869-9 currents and voltages, with a fault on phase A every 10 s.

    sudo python examples/merging_unit.py eth1 [--seconds 30] [--comtrade fault.cfg IA,IB,IC,,,,VA,VB,VC]

With --comtrade, the record replaces the waveforms every 10 s instead of the synthetic fault.
"""

import argparse
import time

from open61850.comtrade import load_comtrade
from open61850.sv import Fault, Playback, Publisher, SvStream, three_phase


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("iface")
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--comtrade", nargs=2, metavar=("CFG", "CHANNELS"))
    args = parser.parse_args()

    rate = 4800
    waves = three_phase(i_peak=100, v_peak=63500 * 2**0.5, i_lag_deg=30)  # 6I3U: Ia Ib Ic Ires In Ih Va Vb Vc
    stream = SvStream(
        sv_id="IED01_MU01_SV1", app_id=0x4000, dst_mac="01:0c:cd:04:00:01", src_mac="02:00:00:00:00:01",
        waves=waves, conf_rev=1, smp_synch=2, vlan_id=100, vlan_priority=4,
        fault=Fault(three_phase(i_peak=100, v_peak=63500 * 2**0.5, i_lag_deg=30, ia_peak=5000, ia_lag_deg=80,
                                va_peak=20000), cycle_s=10, duration_s=0.2),
    )
    if args.comtrade:
        cfg, channels = args.comtrade
        refs = [c or None for c in channels.split(",")]
        stream.playback = Playback.from_comtrade(load_comtrade(cfg), refs, rate, [w.scale for w in waves], repeat_s=10)
    with Publisher(args.iface, rate=rate, asdus_per_frame=2) as publisher:
        publisher.add(stream)
        publisher.start()
        print(f"publishing {stream.sv_id} with the {publisher.engine_name} engine")
        time.sleep(args.seconds)
    print(publisher.stats())


if __name__ == "__main__":
    main()

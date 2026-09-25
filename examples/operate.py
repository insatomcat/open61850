# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Operate a controllable object with its own control model (direct or SBO, normal or enhanced).

    python examples/operate.py 192.0.2.10 IED01_BayLD/CBCSWI1.Pos false
"""

import argparse

from open61850.mms import ControlError, MmsClient, operate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host")
    parser.add_argument("object", help="LD/LN.DO, e.g. IED01_BayLD/CBCSWI1.Pos")
    parser.add_argument("value", choices=["true", "false"], help="ctlVal (for Pos: true closes, false opens)")
    parser.add_argument("--port", type=int, default=102)
    args = parser.parse_args()

    with MmsClient.connect(args.host, args.port) as client:
        try:
            print(operate(client, args.object, args.value == "true"))
        except ControlError as exc:
            raise SystemExit(f"refused: {exc}") from None


if __name__ == "__main__":
    main()

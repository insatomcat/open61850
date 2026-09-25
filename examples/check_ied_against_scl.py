# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Compare an IED's data model with its SCL file (CID, ICD or SCD).

    python examples/check_ied_against_scl.py 192.0.2.10 IED01.cid [--ied IED01]
"""

import argparse

from open61850 import scl
from open61850.mms import MmsClient, discover
from open61850.mms.model import compare


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host")
    parser.add_argument("scl_file")
    parser.add_argument("--ied", help="IED name, when the file has several")
    parser.add_argument("--port", type=int, default=102)
    args = parser.parse_args()

    expected = scl.load_model(args.scl_file, args.ied)
    with MmsClient.connect(args.host, args.port) as client:
        actual = discover(client, list(expected.logical_devices))
    differences = compare(expected, actual)
    print("\n".join(differences) or "the IED matches its SCL")
    raise SystemExit(1 if differences else 0)


if __name__ == "__main__":
    main()

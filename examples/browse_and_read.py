# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Discover an IED's data model and read its measurements.

    python examples/browse_and_read.py 192.0.2.10 [--port 102] [--fc MX]
"""

import argparse

from open61850.display import format_value
from open61850.mms import MmsClient, discover


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--fc", default="MX", help="functional constraint to read (default MX)")
    args = parser.parse_args()

    with MmsClient.connect(args.host, args.port) as client:
        model = discover(client, types=True)
        for device in model.logical_devices.values():
            print(f"{device.name}: {', '.join(device.logical_nodes)}")
        references = list(model.references(fc=args.fc))
        # One request per batch of references, within the negotiated limits.
        for start in range(0, len(references), 20):
            batch = references[start : start + 20]
            for ref, value in zip(batch, client.read_many(batch)):
                node = model.logical_node(ref.ld, ref.ln)
                print(f"{ref} = {format_value(value, node.type_of(ref))}")


if __name__ == "__main__":
    main()

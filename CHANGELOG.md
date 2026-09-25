# Changelog

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

# ESP/ESM parser fixtures

These fixtures are original, synthetic test data created for this repository. They contain no Bethesda game
assets or third-party mod content and are distributed under the repository's GNU Lesser General Public License
version 3.

The payloads use whitespace-separated hexadecimal bytes so every format field stays reviewable. The test suite
materializes them as temporary `.esp` or `.esm` files before calling the public C ABI.

- `valid-roundtrip.esp.hex` contains a minimal `TES4` header, a UTF-8 `BOOK/FULL` value, and an unknown `UNKN`
  subrecord used to verify preservation during modification and round trips.
- `localized.esm.hex` contains a localized `TES4` header and a four-byte `BOOK/FULL` string identifier.
- `malformed-truncated.esp.hex` is the valid fixture with its final byte removed and must be rejected.

New parser bug fixes should add the smallest synthetic fixture or boundary mutation that reproduces the defect.

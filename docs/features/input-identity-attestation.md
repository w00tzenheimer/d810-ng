# Input identity attestation recovery

D810 normally derives its native-analysis identity from IDA's loader-provided
input SHA-256. If IDA no longer supplies that value, D810 fails closed: it
does not run SHA-bound native mutation or use SHA-bound external route-oracle
data.

## What D810 records

When IDA supplies a valid SHA-256, D810 records an attestation in the current
IDB's dedicated netnode, `$ d810.input_identity_attestation.v1`. The record
contains the input SHA-256 and size, a D810 database UUID, IDB creation time,
processor, bitness, imagebase, segment-map digest, and a bounded inventory of
native function fingerprints. Its provenance is `captured_from_ida`.

D810 also mirrors the record to
`<IDA user directory>/d810/input_identity_attestations.sqlite3` for local
diagnostic inspection. The SQLite file is never recovery authority: a missing
or malformed netnode record cannot be recovered from its mirror.

## Optional recovery

Recovery is disabled by default. Enable it explicitly with:

```text
D810_ALLOW_ATTESTED_INPUT_IDENTITY_RECOVERY=1
```

When IDA's loader SHA is missing, D810 accepts the saved SHA only if the
current IDB matches the attested creation time, processor, bitness, imagebase,
segment map, current function RVA, and current function fingerprint.

- If the IDA input path is absent or unreadable, D810 may use matching local
  evidence with provenance `recovered_from_d810_attestation`, but it blocks all
  SHA-bound external route-oracle evidence.
- If the path exists, D810 hashes the file itself. External SHA-bound evidence
  is enabled only when that fresh hash exactly matches the attested SHA-256.
- The filename, input path, IDB path, and SQLite mirror are never identity
  authority.

Each resolved session records its status, provenance, external-evidence gate,
and D810 database UUID in the diagnostic lifecycle timeline under
`input_identity_resolution`.

# D810 Input-Identity Attestation Design

## Goal

Preserve D810's fail-closed native identity contract when IDA temporarily loses
the input SHA-256 loader field, without treating a path, filename, or reusable
project configuration as input identity.

The feature restores only a previously IDA-observed identity for the same IDB.
It never invents an identity and never authorizes SHA-bound external evidence
unless the input file is present and hashes to the attested SHA-256.

## Current failure

`build_native_preanalysis_key()` reads
`ida_nalt.retrieve_input_file_sha256()` directly.  A missing or malformed
digest raises before the native-preanalysis lifecycle can distinguish a loader
metadata loss from a different input.  The gateway consequently reports a
generic identity failure and cannot provide a recovery diagnosis.

## Storage and scope

`InputIdentityAttestation` is a versioned, typed record.  Its authoritative
copy is stored in the IDB-local netnode `$ d810.input_identity_attestation.v1`.
The record includes a randomly generated D810 database UUID.  D810 mirrors
the same record to `$IDAUSR/d810/input_identity_attestations.sqlite3`, keyed
by that UUID, for inspection and repair diagnostics.

The attestation is deliberately absent from project JSON.  Project documents
can be copied between databases and must never carry authority for an input
identity.

Each normal IDA-SHA-backed capture replaces the current attestation and
contains:

- input SHA-256 and input byte size;
- IDB creation time and D810 database UUID;
- processor, bitness, imagebase, and a canonical segment-map digest;
- a bounded, deterministic set of `function RVA -> native byte fingerprint`
  entries, including the function being decompiled;
- capture provenance `captured_from_ida`.

The SQLite mirror is non-authoritative: a missing, malformed, or mismatched
mirror is a warning and does not create recovery authority.  The netnode is
the IDB-local source of truth.  A malformed netnode always disables recovery.

## Resolution policy

The Hex-Rays adapter returns an explicit identity-resolution result rather
than only a SHA string.  It includes the native input identity, provenance,
and whether SHA-bound external evidence is allowed.

| Condition | Native mutation | SHA-bound external evidence |
| --- | --- | --- |
| Valid SHA from IDA | Allowed; refresh attestation | Allowed |
| SHA absent, recovery disabled | Abstain with warning | Denied |
| SHA absent, recovery enabled, attestation does not match current IDB or function | Abstain with mismatch reason | Denied |
| SHA absent, recovery enabled, attestation matches, input path missing | Allowed only for D810-local evidence; provenance is `recovered_from_d810_attestation` | Denied |
| SHA absent, recovery enabled, attestation matches, input path hashes to attested SHA | Allowed | Allowed |
| SHA absent, recovery enabled, existing input path has another hash | Abstain | Denied |

“Matches” requires equality of IDB creation time, processor, bitness,
imagebase, segment-map digest, and the requested function's RVA and native
byte fingerprint.  The IDB path is not an identity component.  It is used
only as a locator for hashing an existing input file.

## User control and diagnostics

Recovery is off by default.  The D810-local setting
`allow_attested_input_identity_recovery` is seeded from
`D810_ALLOW_ATTESTED_INPUT_IDENTITY_RECOVERY`; it is not a project option.

Every missing-SHA resolution logs and emits a typed diagnostic with one of:

- `recovery_disabled`;
- `attestation_missing` or `attestation_malformed`;
- a precise attestation mismatch field;
- `recovered_local_only`;
- `recovered_file_hash_verified`.

The external route-oracle provider receives the resolution authority and
returns no external selection for a local-only recovery.  Existing portable
`NativePreanalysisKey` matching remains strict; the recovery provenance is
kept in backend/session authority rather than added to reusable profile data.

## Implementation boundaries

- Pure core: attestation schema, parsing, comparison, and recovery verdicts.
- Hex-Rays backend: live IDA metadata collection, native function byte
  fingerprints, segment enumeration, file hashing, and native-key assembly.
- Persistence adapter: IDB netnode plus the local SQLite mirror.
- Manager/lifecycle: bind resolution authority to the decompilation session
  and gate external oracle providers.
- Observability: persist warnings and recovery provenance without allowing a
  diagnostic failure to change mutation behavior.

## Acceptance tests

1. A valid IDA SHA writes matching netnode and SQLite attestations.
2. Missing SHA abstains by default with an actionable warning.
3. Enabled recovery accepts only a fully matching attestation and requested
   function fingerprint.
4. A recovered identity without an input file permits local D810 evidence but
   cannot select SHA-bound external oracle data.
5. A present input file must hash to the attested SHA before external evidence
   is enabled.
6. Changing creation time, processor, bitness, imagebase, segment map, RVA,
   or function bytes rejects recovery with the exact mismatch category.
7. Missing/malformed netnode or SQLite mirror remains fail-closed; the mirror
   alone never recovers authority.

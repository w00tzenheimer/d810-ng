# Rhad Second GENERATED Operation Design

## Status and bounded objective

This design amends active ticket `lrea-t5gy` without closing or restarting it.
The already accepted `0x40A605` `cmov`-selected conditional route remains a
permanent regression. This vertical adds the earliest unproved reference-order
`simple_indirect_jump` operation:

- operation: `route:rhad-direct@0x40A619`;
- donor symbol: `JumpInliner._fixup_jmp_and_possible_jcc`;
- source native corridor: `0x40A607`, `0x40A615`, `0x40A617`, `0x40A619`;
- transfer EA: `0x40A619`;
- direct semantic target: `0x40A61B`;
- imported target closure anchors: `0x40A61B`, `0x40A62D`, `0x40A631`,
  `0x40A740`, `0x40A74A`;
- boundary exits: `0x40A633`, `0x40A74C`;
- predicate or flag producer: none.

Success means the same manager-owned GENERATED producer compiles the accepted
conditional route and this direct route as one immutable plan, publishes both
through one shared-coordinator transaction and one receipt, and proves their
semantics through PREOPT, authoritative CFG, CALLS, and CMAT_FINAL. It does not
mean complete A560 restoration.

## Reference inventory and selection

The pinned donor commit is
`21b0d4783703bc4fb6910cfae51d92cd683d2c65`. The unchanged input fixture is
identified by SHA-256
`2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`.

The full reference-order inventory contains 228 indirect-jump operations:

| Variant | Count |
|---|---:|
| `cmov_selected_indirect` | 39 |
| `simple_indirect_jump` | 64 |
| `existing_conditional_plus_indirect` | 117 |
| `setcc_indexed_table` | 8 |

Every inventory row records the reference symbol and variant, source and
transfer native EAs, predicate or flag producer, semantic targets, owned
corridor, imported closure, boundary exits, compiler support, and GENERATED
proof status. Where the current portable source-plan graph cannot establish a
closure root, the row records the typed unmet obligation
`root_unavailable_in_current_portable_source_plan`; it does not guess.

The accepted route is reference row 1. The selected operation is reference row
2 and is the earliest unproved `simple_indirect_jump`.

## Corrected publication contract

The combined plan remains
`FragmentPublicationPurpose.FRONTEND_NORMALIZATION`. Changing it to canonical
semantic lowering is incorrect: canonical plans cannot retain the frontend
work-item scope, and the accepted replacement-root computed normalization at
`0x40A605` does not have imported-body proof.

`FragmentPlan` admits a direct transfer rewrite under frontend normalization
only when all of these typed facts hold:

1. the operation has `FragmentReferenceRouteAuthority`;
2. its source is an `IMPORT_NATIVE` block owned by a `FragmentNativeBody`;
3. its operation id is present in that body's `proof_ids`;
4. its operation id is present in the plan's
   `FragmentWorkItemScope.selected_obligation_ids`;
5. the plan has a `RouteOracleRun` matching the native input and function;
6. the reference route final kind, target, owner, rewrite anchor, and direct
   edge match the `FragmentDirectTransferRewrite`;
7. the existing stable identity, delivery-region ownership, and native-key
   constraints all pass.

The existing canonical route-proof contract remains valid and unchanged. An
unreferenced frontend direct rewrite, an operation omitted from body proof or
work scope, a foreign oracle run, or a mismatched target rejects during plan
construction, before any live mutation.

## Portable compiler vocabulary

The pure compiler adds an immutable `RhadDirectRoute` alongside
`RhadConditionalRoute`. It contains no live IDA object, serial number, optional
compatibility field, or untyped metadata. Its required facts are:

- operation and source block identities;
- transfer and owner anchor EAs;
- direct target block identity;
- owned corridor instruction EAs;
- imported closure block identities and boundary exits;
- reference phase, category, provenance, and ordered dependencies.

Compilation validates the source as imported native-body evidence, ensures the
target belongs to the route's declared imported closure, and emits exactly one
direct edge, one `FragmentDirectTransferRewrite`, and one direct
`ReferenceRouteRewrite`. Unsupported variants reject with the first typed
failed obligation.

The compiler permits each operation to declare its own exact closure. The
union of operation closures must equal the imported blocks in the base plan.
The batch boundary authority is derived from the union of operation boundary
exits after removing exits internalized by another operation's imported
closure. For the two-operation batch:

- the accepted conditional closure contributes nine blocks;
- the selected direct closure contributes five blocks;
- the combined imported closure contains fourteen blocks;
- `0x40A61B` becomes internal to the batch;
- final external exits are `0x40A633`, `0x40A68C`, `0x40A74C`, `0x40B790`.

Per-operation closure and boundary evidence remains serialized in each
reference-route payload.

## Generic producer and preparation

The manager owns one typed reference-batch registry. Selection is by the
current `NativePreanalysisKey` and immutable reference evidence, not by an
imperative `if function_ea == 0x40A560` or `if transfer_ea == 0x40A605` guard.
Exact A560 EAs are evidence data and test fixtures, not dispatch logic.

The existing producer prepares all target-rooted native fragments named by the
selected batch. It captures three roots for this batch: `0x40A607`, `0x40B6C0`,
and `0x40A61B`. The preparation algorithm continues to derive owned ranges,
boundary ranges, and exits from the portable source plan. It does not call
`mba.build_graph()` on the live GENERATED MBA.

At actual `MMAT_GENERATED` the producer compiles the batch and invokes
`HexRaysMutationBackend.apply` once with
`GENERATED_GRAPH_FREE`. The current FragmentPlan-to-PatchPlan lowering, final
binding, `CfgTransactionCoordinator`, mutation gateway, deferred modifier,
creation witnesses, and receipt remain the only transaction path.

CALLS only invokes the maturity observer. It performs no planning, mutation,
or redo.

## Diagnostics and semantic canaries

The compiled event persists ledger identity, reference provenance, ordered
operation ids, per-operation closures and exits, combined imported identities,
and final batch exits. The publication event records one batch and one complete
receipt. Planned identities plus creation witnesses must reconstruct every
created block.

The accepted conditional canary remains exact: while its source topology
exists, the indirect transfer at `0x40A605` is absent and the semantic targets
are `0x40A607` and `0x40B6C0`.

The selected direct canary is exact: while `native@0x40A619` exists, its
indirect transfer is absent and its direct target is `0x40A61B`. If Hex-Rays
legitimately optimizes the source block away, the whole function must contain
no residual indirect transfer attributable to `0x40A619`, and the required
reachable downstream semantics at `0x40A633` and `0x40A74C` remain represented
for as long as their source topology exists.

The successful receipt is committed and unpoisoned. There is no rollback,
redo, alternate mutation path, numeric INTERR, or CALLS mutation. Ctree must
reach CMAT_FINAL.

## Verification and commit boundaries

The implementation is accepted only after:

- the accepted `0x40A605` checksum and new operation checksum pass;
- focused compiler, plan-admission, preparation, and publication tests pass;
- transaction/runtime and named protected-family suites pass;
- the strict 41-row gate passes;
- ast-grep and all import-linter contracts pass from this worktree;
- the input binary SHA-256 is unchanged;
- diagnostic SQLite evidence proves GENERATED through CMAT_FINAL;
- `graphify update .` completes;
- compiler vocabulary, operation semantics, diagnostics, and any regression
  repair are committed separately.

The two known broad dispatcher-pattern DSL failures remain non-acceptance
evidence and are not in scope unless one directly blocks this route or the
protected-family matrix.

# Interpreting unflatten outcome diagnostics

`UNFLAT_OUTCOME` and `unflat-why` display
`preplan_reachable_handlers=N/M`. The persisted fields are still named
`handlers_recovered` and `handlers_total` for database compatibility. This
count is computed by `_reachability` in `minimal_unflatten_emit.py` from the
current portable graph and preliminary graph modifications. It is **not**
measured on the final native CFG. In particular, it cannot account for a
later typed `PatchEdgeSplitCorridor` transaction step. A value below `M`
does not, by itself, mean a handler was lost by the committed rewrite.

The corridor forecast's persisted `full_unflattening_claim=False` is also
not a failed handler-coverage check. The property is deliberately always
false: topology coverage does not prove whole-function semantic equivalence.
The human-facing coverage log renders this as
`whole_function_proof=not_claimed`. Do not flip the flag merely because all
handlers are reachable in a final graph.

## Example: 69814 loader, RVA 0x118c0

On the 69814 loader run for `sub_7FFF991818C0`, the pre-plan counter was
`102/103` and named `blk89@0x7FFF99183CB6` as unreached. That was an
intermediate projection. A subsequently selected edge-split route from
`blk179@0x7FFF99187086` targeted that handler with state `0x50D99DE2`.
In the post-transaction native snapshots, Hex-Rays had merged and renumbered
blocks: the reachable conditional at `blk48@0x7FFF9918689A` leads to
`blk59@0x7FFF9918705F`, which contains the original instruction at
`0x7FFF99183CB6`, and then to `blk63@0x7FFF99187D3D`. The original handler
was not dropped. These serials are snapshot-local; compare EA anchors and
instruction membership, not serial numbers alone.

This establishes preservation of that conditional path in the observed
final native graph. It does **not** supply a concrete input that takes the
branch, prove the original state feasible, or prove whole-function semantic
equivalence. For any future partial pre-plan count, inspect the exact
transaction steps and a post-transaction native graph before describing
the final outcome. A trustworthy final reachability metric would need an
explicit cross-snapshot EA/instruction mapping and its own validation;
do not relabel the pre-plan number as that metric.

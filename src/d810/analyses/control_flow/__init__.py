"""Portable control-flow graph algorithms (LLVM / LiSA-style).

``d810.analyses.control_flow`` hosts backend-neutral CFG analyses:
dominators, reachability, SESE regions, and the state-machine / dispatcher
recognition graph algorithms relocated out of ``d810.recon.flow`` (BST
interval maps, dispatcher node models, snapshot-only topology helpers).

Portable-core layer: no live IDA / Hex-Rays imports, no vendor mutation
surfaces (enforced by the ``portable-core-*`` import-linter contracts and
the ``no-*-in-portable-core`` ast-grep rules).  Hex-Rays evidence walkers
that duck-type live ``mba``/``mop`` objects belong in
``d810.backends.hexrays.evidence``, not here.

See ``docs/plans/recon-and-cfg-restructuring.md`` (Suggested Landing
Sequence, step 6) and the migration playbook for the relocation slice.
"""

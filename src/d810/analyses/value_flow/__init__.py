"""Portable value-flow facts and analyses (LLVM / LiSA-style).

``d810.analyses.value_flow`` hosts backend-neutral value-flow analyses:
def-use, value ranges, aliasing, recurrence/induction facts, and the
constant-folding / state-write evaluation core relocated out of
``d810.recon.flow``.

Portable-core layer: no live IDA / Hex-Rays imports, no vendor mutation
surfaces.  Live-mba accessors are injected by the Hex-Rays evidence adapter
(``d810.backends.hexrays.evidence``) rather than imported here.

See ``docs/plans/recon-and-cfg-restructuring.md`` (Suggested Landing
Sequence, steps 6-8) and the migration playbook for the relocation slices.
"""

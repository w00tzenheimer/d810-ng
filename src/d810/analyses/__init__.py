"""Portable analysis layer (LLVM / LiSA-style).

``d810.analyses`` hosts backend-neutral program analyses: data-flow
fixpoint machinery (``data_flow``), control-flow graph algorithms
(``control_flow``), and value-flow facts (``value_flow``).

The layer is portable-core: it must not import live IDA / Hex-Rays APIs
or vendor mutation surfaces.  This is enforced statically by the
``portable-core-no-ida`` / ``portable-core-no-vendor-mutation``
import-linter contracts and the ``no-live-ida-in-portable-core`` /
``no-vendor-identifier-in-portable-core`` ast-grep rules.

See ``docs/plans/recon-and-cfg-restructuring.md`` (Suggested Landing
Sequence, step 3) for the migration that introduces this package.
"""

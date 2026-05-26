"""Portable transform layer for d810.

Per the LLVM/LiSA-style taxonomy in
``docs/plans/recon-and-cfg-restructuring.md``, this package hosts
abstract transform contracts (Protocols) that are backend-neutral --
they describe the SHAPE of an optimization, not its Hex-Rays / angr /
Ghidra implementation.

Concrete transform implementations (e.g. Hex-Rays microcode rewrites)
live under ``d810.optimizers`` and ``d810.backends.hexrays``; they
satisfy the Protocols here structurally.

This package must remain IDA-free at import time -- enforced by
``rules/no-live-ida-in-portable-core.yml``.
"""

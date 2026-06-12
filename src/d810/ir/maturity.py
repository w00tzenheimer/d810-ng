"""Backend-agnostic IR maturity levels (ticket llr-a93i).

A *maturity* names HOW MUCH analysis the decompiler IR has had — independent of which
backend produced it. Portable analyses and unflatten profiles declare the maturity
their pattern is recoverable at in these terms, so the same declaration applies to any
IR backend; an IDA / Hex-Rays *adapter*
(:mod:`d810.hexrays.ir_maturity`) maps these to ``ida_hexrays.MMAT_*`` constants. The
mapping for each backend is recorded per member below.

Portable: pure ``enum`` — NO ``ida_*`` import (this module is portable-core; the live
mapping lives in the vendor adapter).
"""
from __future__ import annotations

from enum import Enum


class IRMaturity(str, Enum):
    """Backend-agnostic decompiler IR maturity levels (ordered lift → pseudocode)."""

    # Hex-Rays: MMAT_GENERATED | Ghidra: raw instruction P-code | Binary Ninja: LLIL
    # Meaning: direct lift from machine code.
    LIFTED = "ir.lifted"
    # Hex-Rays: MMAT_PREOPTIMIZED | Ghidra: early/canonicalized P-code
    # Binary Ninja: LLIL after canonical cleanup | Meaning: instruction semantics normalized.
    CANONICAL = "ir.canonical"
    # Hex-Rays: MMAT_LOCOPT | Ghidra: locally simplified decompiler P-code | Binary Ninja: MLIL
    # Meaning: local propagation, temp folding, expression cleanup.
    LOCAL_OPTIMIZED = "ir.local.optimized"
    # Hex-Rays: MMAT_CALLS | Ghidra: High P-code after call analysis
    # Binary Ninja: MLIL with call/prototype recovery
    # Meaning: calls, arguments, returns, and prototypes modeled.
    CALL_MODELED = "ir.call.modeled"
    # Hex-Rays: MMAT_GLBOPT1 | Ghidra: HighFunction after global dataflow | Binary Ninja: MLIL SSA
    # Meaning: global def-use/dataflow facts are available.
    GLOBAL_ANALYZED = "ir.global.analyzed"
    # Hex-Rays: MMAT_GLBOPT2 | Ghidra: heavily simplified HighFunction
    # Binary Ninja: MLIL SSA / early HLIL | Meaning: stronger global simplification and DCE.
    GLOBAL_OPTIMIZED = "ir.global.optimized"
    # Hex-Rays: MMAT_GLBOPT3 | Ghidra: final High P-code before C emission | Binary Ninja: HLIL
    # Meaning: structured high-level control flow.
    STRUCTURED = "ir.structured"
    # Hex-Rays: MMAT_LVARS | Ghidra: recovered local-variable model
    # Binary Ninja: HLIL with variable recovery
    # Meaning: pseudocode-ready local variable abstraction.
    VARIABLE_RECOVERED = "ir.variable.recovered"

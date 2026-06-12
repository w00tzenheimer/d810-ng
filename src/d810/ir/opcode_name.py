"""Portable micro-opcode name enum (migration bridge).

``OpcodeName`` is a ``(str, Enum)`` whose member *values* are the Hex-Rays
micro-opcode mnemonics (``"m_jz"`` ...).  It exists so portable-core code can
reference an ENUM MEMBER (``OpcodeName.JZ``) instead of a bare vendor string
(``"m_jz"``), per the "enums over strings, always" preference -- while staying
byte-for-byte behaviour-neutral: a ``(str, Enum)`` member compares AND hashes
equal to its string value, so ``field == OpcodeName.JZ`` is identical to the
old ``field == "m_jz"`` (and works as a dict key against plain-string lookups).

This is a TRANSITIONAL bridge, NOT the end-state vocabulary:

* The vendor mnemonic survives only as the member VALUE, in this one
  definition -- not scattered across ~150 comparison sites.
* The end-state normalized op vocabulary (P-Code-style ``OpKind`` with
  signedness in the op) is consolidation slice S3 (``llr-2rhc``); when it
  lands, the converter produces it directly and the member values here can be
  retired without touching any comparison site (they reference the member).
* Only the distinct opcodes actually used in portable-core today are enrolled;
  add members as new ones appear (the converter is the source of truth).

The ``str`` mixin keeps it JSON/sqlite serialisable. NOTE the ``(str, Enum)``
``__str__`` gotcha: ``str(OpcodeName.JZ)`` is ``"OpcodeName.JZ"``, not
``"m_jz"`` -- so only swap STRING-LITERAL COMPARISONS onto members, never a
literal that gets ``str()``/f-string-formatted. The codemod that performs the
swap (``tools/scripts/codemod_vendor_string_to_enum.py``) enforces this by
rewriting only literals in ``==`` / ``!=`` / ``in`` positions.
"""
from __future__ import annotations

from enum import Enum


class OpcodeName(str, Enum):
    """Hex-Rays micro-opcode mnemonic, as a portable enum member."""

    # arithmetic / logic
    ADD = "m_add"
    SUB = "m_sub"
    MUL = "m_mul"
    OR = "m_or"
    AND = "m_and"
    XOR = "m_xor"
    # moves / conversions
    MOV = "m_mov"
    STX = "m_stx"
    XDU = "m_xdu"
    XDS = "m_xds"
    NOP = "m_nop"
    # set-on-condition
    SETB = "m_setb"
    SETAE = "m_setae"
    SETA = "m_seta"
    SETBE = "m_setbe"
    SETG = "m_setg"
    SETGE = "m_setge"
    SETL = "m_setl"
    SETLE = "m_setle"
    # conditional jumps
    JCND = "m_jcnd"
    JZ = "m_jz"
    JNZ = "m_jnz"
    JB = "m_jb"
    JAE = "m_jae"
    JA = "m_ja"
    JBE = "m_jbe"
    JG = "m_jg"
    JGE = "m_jge"
    JL = "m_jl"
    JLE = "m_jle"
    # control transfer
    GOTO = "m_goto"
    IJMP = "m_ijmp"
    CALL = "m_call"
    ICALL = "m_icall"
    RET = "m_ret"

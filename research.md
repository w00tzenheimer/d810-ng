The research report is written to `research.md`. Here's the executive summary:

---

## Key Findings

### The Core Gap — One Pattern Out of ~20 Useful Opcodes

`_resolve_mop_via_def_use` handles exactly **one case**:
```python
if def_insn.opcode == m_mov and def_insn.l.t == mop_n:  # literal constant only
    return def_insn.l.nnn.value
return None  # everything else → synthetic value or EmulationException
```

### What's Missing (Prioritized)

| Priority | Opcodes | Why Critical |
|---|---|---|
| **P1 — Critical** | `m_mov` (reg/stack src), `m_xdu`, `m_xds`, `m_low` | Copy propagation + width extension — appear in *every* obfuscated function |
| **P2 — High** | `m_add`, `m_sub`, `m_xor`, `m_or`, `m_and`, `m_neg`, `m_bnot` | The core MBA opcode set; deobfuscation targets these directly |
| **P3 — Medium** | `m_shl`, `m_shr`, `m_sar`, `m_mul`, `m_high` | Complete the arithmetic ISA |
| **P4 — Low** | `m_lnot`, `m_udiv`, `m_sdiv`, `m_umod`, `m_smod`, flags | Rarely obfuscated directly |

### The High-Leverage Fix

`_eval_instruction` **already implements all of these correctly**. The fix is a **single change**: after locating the defining instruction, insert a cycle-break sentinel into `_def_use_cache`, then delegate to `_eval_instruction`. This unlocks recursive constant folding through arbitrary def-use chains (copy → extend → add → xor → …) with zero new arithmetic code.

Two secondary issues also flagged:
1. `_def_use_cache` uses Python object identity hashing on SWIG `mop_t` objects — cache hits likely very rare in practice
2. Cross-block `environment.set_cur_flow` needs save/restore to avoid polluting the caller's context
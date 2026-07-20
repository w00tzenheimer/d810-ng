# d810 Backends

This package hosts vendor-specific backend implementations for d810,
organized by **domain** then **vendor / engine** per the llvm-lisa-restructure
plan's ``d810.backends/<domain>/<vendor>.py`` convention.

## Architecture

Current layout:

```
src/d810/backends/
├── __init__.py
├── README.md           # This file
├── ast/                # AST + SMT backends for the AstNode IR
│   ├── __init__.py
│   ├── pattern_matching.py
│   └── z3.py           # Z3 prover over IDA AstNode / mop_t
├── emulation/          # Concrete evaluator backends
│   ├── __init__.py
│   ├── common.py
│   ├── oracle.py
│   └── triton.py       # Triton-based concrete execution
├── facts/              # Vendor lifters for substrate fact collectors
│   ├── __init__.py
│   └── ida.py          # IDA mba_t → InductionVariableFactCollector lifter
└── mba/                # MBA-expression backends (the original "MBA Backends")
    ├── __init__.py
    ├── egglog_backend.py
    ├── egraph.py
    ├── ida.py          # IDA pattern-matching adapter
    └── z3.py           # Z3 prover over pure SymbolicExpression
```

Planned (per ``docs/plans/preanalysis-and-cfg-restructuring.md``):

- ``backends/hexrays/{lifter,capabilities,mutation,evidence}.py`` --
  the central Hex-Rays integration; ``lifter.py`` produces portable
  ``FlowGraph`` snapshots, ``capabilities.py`` implements abstract
  capability Protocols (e.g. ``ConstantFixpointCapability``),
  ``mutation.py`` owns the deferred-modifier mutation surface,
  ``evidence/`` hosts live-mba evidence adapters that don't yet have
  abstract cross-backend contracts (e.g. dead-state-var evidence).
- ``backends/angr/{lifter,capabilities}.py`` -- future angr backend.
- ``backends/ghidra/{lifter,capabilities}.py`` -- future Ghidra backend.

## MBA backends (this section retained for compat; the rest of the
## README describes the per-backend module APIs)

## Available Backends

### 1. Z3 Backend (`z3.py`)

**Purpose:** Theorem proving and equivalence checking
**Dependencies:** `z3-solver` (optional)
**Status:** ✅ Complete

**API:**
```python
from d810.backends.mba.z3 import z3_prove_equivalence, Z3_INSTALLED

if Z3_INSTALLED:
    is_equiv, counterexample = z3_prove_equivalence(pattern, replacement)
```

**Key functions:**
- `z3_prove_equivalence()` - Prove two expressions are equivalent
- `Z3VerificationVisitor` - Convert SymbolicExpression to Z3 bitvector expressions
- `get_solver()` - Get configured Z3 solver instance

**Use cases:**
- Verifying MBA rule correctness (used by `MBARule.verify()`)
- Proving optimization correctness

**Note:** This backend is pure Python (no IDA). For IDA-specific Z3 verification,
see `d810.backends.ast.z3.Z3MopProver`.

### 2. IDA Backend (`ida.py`)

**Purpose:** Adapt VerifiableRule for IDA pattern matching, convert SymbolicExpression to AstNode
**Dependencies:** IDA Pro SDK
**Status:** ✅ Complete

**API:**
```python
from d810.backends.mba.ida import IDAPatternAdapter, IDANodeVisitor, adapt_rules

# Adapt rules for IDA integration
ida_rules = adapt_rules(rule_instances)

# Use adapter directly
adapter = IDAPatternAdapter(my_rule)
new_ins = adapter.check_and_replace(blk, instruction)

# Convert DSL expression to AstNode
visitor = IDANodeVisitor()
ast_node = visitor.visit(pattern)
```

**Key classes:**
- `IDAPatternAdapter` - Wraps a VerifiableRule for IDA pattern matching
- `IDANodeVisitor` - Converts SymbolicExpression trees to IDA AstNode trees
- `adapt_rules()` - Batch wrap rules with IDAPatternAdapter

### 3. E-graph Backend (`egglog_backend.py`)

**Purpose:** E-graph pattern matching and equivalence verification
**Dependencies:** `egglog` (optional)
**Status:** ✅ Complete

**Planned API:**
```python
from d810.backends.mba.egraph import MBARuleset, EGraphSimplifier
from d810.mba import Var

# Create ruleset from verified MBA rules
ruleset = MBARuleset([XorRule1(), XorRule2()])
ruleset.verify_all()  # Z3 proves correctness

# Create simplifier
simplifier = EGraphSimplifier(ruleset)

# Optimize expression
x, y, z = Var("x"), Var("y"), Var("z")
complex = ((x + y) - 2*(x & y) | z) - ((x + y) - 2*(x & y) & z)
simple = simplifier.simplify(complex)
print(simple)  # x ^ y ^ z
```

**Key advantages:**
- Automatic chain discovery (multi-step simplifications in one pass)
- Bidirectional rewrites (explore all equivalent forms)
- Optimality guarantees (saturation proves best form found)
- Subexpression sharing (automatically handles common subexpressions)

**See also:** `docs/EGRAPH_DESIGN.md` for comprehensive design

## Backend Selection

Backends are **optional** and can be used independently:

```python
# Check what's available
from d810.backends import Z3_INSTALLED

if Z3_INSTALLED:
    print("Z3 verification available")
```

Each backend handles its own imports gracefully:
- Missing Z3 → verification disabled, but DSL still works
- Missing IDA → pure Python mode, standalone tools work
- Missing e-graph → pattern matching fallback

## Design Principles

1. **Optional dependencies** - Each backend is optional, core DSL always works
2. **Clean separation** - Each backend is self-contained
3. **Graceful degradation** - Missing backends don't break other functionality
4. **Forward compatibility** - Adding new backends doesn't break existing code

## Module Layout

```python
# IDA-specific Z3 verification (AstNode/mop_t)
from d810.backends.ast.z3 import Z3MopProver

# Pure symbolic verification (SymbolicExpression, no IDA)
from d810.backends.mba.z3 import z3_prove_equivalence
```

## Adding a New Backend

To add a new backend, place it under the right ``<domain>`` per the
layout above:

1. Create ``src/d810/backends/<domain>/<vendor>.py``
   (e.g. ``src/d810/backends/mba/mybackend.py`` for an MBA-domain
   backend; ``src/d810/backends/hexrays/lifter.py`` for the Hex-Rays
   IR lifter).
2. Implement backend-specific logic.
3. Export public API in the domain's ``__init__.py``.
4. Add documentation here (or under
   ``src/d810/backends/<domain>/README.md`` for domain-local detail).
5. Add tests in ``tests/unit/<domain>/<vendor>/`` (or under
   ``tests/system/runtime/...`` if the backend requires live IDA).

Example structure (MBA-domain backend):
```python
# src/d810/backends/mba/mybackend.py
"""My custom backend for MBA expressions."""

# Check optional dependency
try:
    import mylib
    MYLIB_AVAILABLE = True
except ImportError:
    MYLIB_AVAILABLE = False

def my_function(expr):
    if not MYLIB_AVAILABLE:
        raise ImportError("mylib not installed")
    # Implementation...

__all__ = ["MYLIB_AVAILABLE", "my_function"]
```

## Future Backends

Potential future backends:
- **LLVM backend** - Convert to/from LLVM IR
- **SMT backend** - Use different SMT solvers (CVC5, Yices)
- **Symbolic execution** - Integrate with angr, manticore
- **Custom simplifier** - Hand-rolled MBA simplification heuristics

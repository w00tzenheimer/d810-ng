# MBA Backends

This package contains different backend implementations for working with MBA expressions.

## Architecture

```
d810/mba/backends/
├── __init__.py         # Package exports
├── z3.py               # Z3 SMT solver backend (for verification)
├── ida.py              # IDA Pro integration
├── egglog_backend.py   # E-graph pattern matching (optional, requires egglog)
└── README.md           # This file
```

## Available Backends

### 1. Z3 Backend (`z3.py`)

**Purpose:** Theorem proving and equivalence checking
**Dependencies:** `z3-solver` (optional)
**Status:** ✅ Complete

**API:**
```python
from d810.mba.backends.z3 import z3_prove_equivalence, Z3_INSTALLED

if Z3_INSTALLED:
    is_equiv, counterexample = z3_prove_equivalence(pattern, replacement)
```

**Key functions:**
- `z3_prove_equivalence()` - Prove two expressions are equivalent
- `ast_to_z3_expression()` - Convert AST to Z3 bitvector expression
- `get_solver()` - Get configured Z3 solver instance
- `z3_check_mop_equality()` - IDA mop_t equality checking (legacy)

**Use cases:**
- Verifying MBA rule correctness (used by `MBARule.verify()`)
- Checking instruction equivalence in IDA
- Proving optimization correctness

**Note:** This backend has some IDA dependencies for legacy `z3_check_mop_equality()`
functions. The pure MBA verification via `z3_prove_equivalence()` works without IDA.

### 2. IDA Backend (`ida.py`)

**Purpose:** Adapt VerifiableRule for IDA pattern matching, convert SymbolicExpression to AstNode
**Dependencies:** IDA Pro SDK
**Status:** ✅ Complete

**API:**
```python
from d810.mba.backends.ida import IDAPatternAdapter, IDANodeVisitor, adapt_rules

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
from d810.mba.backends.egraph import MBARuleset, EGraphSimplifier
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
from d810.mba.backends import Z3_INSTALLED

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

## Backward Compatibility

**Old locations still work:**
```python
# Old (still works for IDA integration)
from d810.expr.z3_utils import z3_check_mop_equality

# New (for pure MBA framework)
from d810.mba.backends.z3 import z3_prove_equivalence
```

The old `d810.expr.z3_utils` is kept for backward compatibility with existing
d810 optimizers. New code should use `d810.mba.backends.z3` for pure verification.

## Adding a New Backend

To add a new backend:

1. Create `d810/mba/backends/<name>.py`
2. Implement backend-specific logic
3. Export public API in `__init__.py`
4. Add documentation here
5. Add tests in `tests/unit/mba/backends/`

Example structure:
```python
# d810/mba/backends/mybackend.py
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

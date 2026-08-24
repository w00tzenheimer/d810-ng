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

Egglog-based MBA extraction is supplied by the optional `d810-egglog`
extension.  Core owns the portable typed-term catalogue, native matcher, and
Z3 proof boundary; it does not ship an in-tree Egglog backend.

## Backend Selection

Backends are **optional** and can be used independently. Ask the registry
rather than reaching for a per-module flag:

```python
from d810.backends import registry

solver = registry().optional("cobra")   # None if unusable; never raises
if solver is not None:
    ...
```

To find out *why* something is unusable:

```console
$ python tools/d810cli.py backends
d810: /path/to/checkout/src/d810/__init__.py
ast.z3             unavailable   builtin
                   -> No module named 'ida_hexrays'
cobra              available     builtin
emulation.triton   available     builtin
emulation.unicorn  available     builtin
llvm               available     builtin
mba.z3             available     builtin
```

Backends are named `<domain>.<vendor>`, mirroring the module layout -- which
also makes the two-Z3 distinction warned about above visible here rather than
buried in a docstring. `facts` and `hexrays` are deliberately not registered:
they are the IDA vendor spine, not optional backends.

Exit code 0 means every backend is usable or expectedly absent; 1 means a
backend is `BROKEN` (raised on import) or `INCOMPATIBLE` (built against a
protocol version this d810 no longer speaks). A missing optional dependency is
**not** a failure.

Each backend degrades gracefully:
- Missing Z3 → verification disabled, but DSL still works
- Missing IDA → pure Python mode, standalone tools work

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

try:
    import mylib
except ImportError as exc:
    mylib = None
    _WHY = str(exc)


def d810_backend_probe() -> str | None:
    """Plugin protocol hook: None if usable, else a human-readable reason."""
    return None if mylib is not None else f"mylib not installed: {_WHY}"


def my_function(expr): ...
```

Then add it to `BUILTIN_BACKENDS` in `d810/backends/__init__.py`.

**Why the probe hook and not just a module flag.** Importing successfully is
not evidence a backend works. Every backend here imports cleanly whether or not
its dependency is present -- `mba.z3` sets `Z3_INSTALLED = False` and carries
on, `emulation.triton` sets `TRITON_AVAILABLE = False`, `cobra.solve` works
with or without its compiled `_cobra` extension. Without a hook the registry
would report all of them `available`.

A flag also collapses two different events -- "optional dependency absent"
(normal) and "this plugin is buggy" (someone must fix it) -- so a backend
raising `AttributeError` on import gets silently filed as "not installed". The
registry keeps them apart as `UNAVAILABLE` vs `BROKEN`, and only the latter
exits non-zero.

The remaining legacy flags (`Z3_INSTALLED`, `TRITON_AVAILABLE`, and
`UNICORN_AVAILABLE`) are unchanged and remain authoritative; the hooks read
them. Existing code keeps working.

### Out-of-tree backends

A separate distribution announces itself with an entry point in the
`d810.backends` group. The group name carries **no version** -- versioning it
would churn the group on every protocol bump and force every extension author
to notice. The version belongs to the extension, declared in its **manifest**:

```toml
# pyproject.toml of some d810-backend-mything distribution
[project.entry-points."d810.backends"]
mything = "d810_backend_mything:MANIFEST"
```

```python
# d810_backend_mything/__init__.py
MANIFEST = {
    "name": "mything",
    "api_version": 1,
    "provides": "d810_backend_mything.heavy:api",   # resolved LAZILY
}
```

The entry point resolves to the *manifest*, not the backend, and the manifest
must be cheap to import. `provides` is resolved only after the version check
passes, so **a rejected plugin never imports its heavy half** -- no native
extension, no z3, nothing. The module named by `provides` may import d810
freely; it runs long after d810 has finished loading.

`BackendManifest` is importable from `d810.core.plugins` if you want a typed
declaration; a plain dict works identically.

Discovery is lazy (an `entry_points()` scan measures ~31 ms cold) and failure
is contained: a plugin that explodes on import is reported as `BROKEN` and
degrades only itself.

**A stale plugin will not disable a working builtin.** Candidates are tried in
order -- entry points first, builtin last -- and an unusable one falls through
with the reason recorded:

```console
mba.z3  available     builtin
        !! rejected d810-z3ng 0.1: built for plugin API v99; this d810 speaks v1
```

That still exits 1, so degrading to a fallback cannot pass silently in CI.

In-tree backends are a **static table**, not entry points, because d810 is
deployed as a symlink into a source checkout while `pip` metadata for `d810-ng`
may separately exist at a *different version* -- trusting entry points for
builtins would let the backend list describe one version while another
executes.

Hot reload treats the entry point's manifest module as the extension-owned
reload prefix. D810 snapshots those declarations, stops the old plugin, and
uses the generic reloader's exact-prefix eviction primitive. The reloader then
rebuilds only `d810.*`; it does not discover providers or decide their order.
Afterward a newly constructed D810 state creates a new `BackendRegistry`, reads
the installed entry points again, and cold-imports every declared rule module
against the rebuilt core. This keeps rule classes and portable contract types
from surviving with stale identities.

An extension must not import while the D810 core is still reloading. D810 checks
the snapshotted prefixes before constructing the replacement plugin and aborts
hot reload if one has reappeared. Restart IDA after that failure: Python class
identity changes cannot be rolled back transactionally.

If D810-coupled runtime code lives outside the manifest package, declare the
additional exact module prefix rather than relying on shared-namespace
inference:

```python
MANIFEST = {
    "name": "mything",
    "api_version": 1,
    "provides": "company.mything_runtime:api",
    "reload_modules": ("company.mything_runtime",),
}
```

Do not declare a broad shared prefix such as `company`: reload preparation
would correctly treat that declaration as ownership and evict sibling modules.
Provider availability does not affect this lifecycle; unavailable and
incompatible extension manifests are also evicted without resolving
`provides`.

## Future Backends

Potential future backends:
- **LLVM backend** - Convert to/from LLVM IR
- **SMT backend** - Use different SMT solvers (CVC5, Yices)
- **Symbolic execution** - Integrate with angr, manticore
- **Custom simplifier** - Hand-rolled MBA simplification heuristics

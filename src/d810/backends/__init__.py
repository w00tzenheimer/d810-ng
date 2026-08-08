"""Backends for MBA expression processing.

This package contains different backend implementations for working with
MBA expressions (d810.mba.dsl.SymbolicExpression):

- z3: Z3 SMT solver backend for verification and equivalence checking
- ida: IDA Pro integration (minsn_t * SymbolicExpression conversion)
- egglog_backend: E-graph backend using egglog (optional)

Each backend is optional and can be used independently based on available
dependencies and use case.

=============================================================================
IMPORTANT: Z3 Module Separation
=============================================================================

There are TWO Z3 modules in d810 - do NOT confuse them:

1. d810.backends.mba.z3 (THIS PACKAGE - pure, no IDA)
   - Works with: SymbolicExpression (platform-independent)
   - Use for: Unit tests, CI, TDD, mathematical verification
   - Exports: Z3VerificationVisitor, prove_equivalence, verify_rule

2. d810.backends.ast.z3 (IDA-specific)
   - Works with: AstNode, mop_t, minsn_t (IDA types)
   - Use for: Runtime verification inside IDA Pro plugin
   - Exports: Z3MopProver, AstNodeZ3Visitor

See the module docstrings in each file for full details.
=============================================================================
"""

from d810.core.plugins import BackendRegistry, BackendSpec, builtin, make_singleton

__all__ = ["BUILTIN_BACKENDS", "registry"]

#: Backends that ship inside d810.
#:
#: A static table, NOT entry points. d810 runs as a symlink into a source
#: checkout while pip metadata for ``d810-ng`` may separately exist at a
#: different version, so entry-point metadata can describe one version while
#: another executes. Entry points are an additive overlay for out-of-tree
#: plugins; see :mod:`d810.core.plugins`.
#:
#: Targets are strings, resolved on first use, so listing a backend here costs
#: nothing until someone asks for it -- and importing this package never drags
#: in z3, IDA, or a native extension.
BUILTIN_BACKENDS: tuple[BackendSpec, ...] = (
    builtin("cobra", "d810.backends.cobra.solve"),
)


#: The process-wide backend registry. Assembled here rather than in
#: ``core.plugins`` so the mechanism stays beneath the backends it serves.
registry = make_singleton(
    lambda: BackendRegistry(builtins=BUILTIN_BACKENDS)
)

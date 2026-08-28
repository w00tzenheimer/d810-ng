"""Backends for MBA expression processing.

This package contains different backend implementations for working with
MBA expressions (d810.mba.dsl.SymbolicExpression):

- z3: Z3 SMT solver backend for verification and equivalence checking
- ida: IDA Pro integration (minsn_t * SymbolicExpression conversion)

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

from d810.core import getLogger
from d810.capabilities.plugin_host import PluginHostCapabilityRegistry
from d810.core.plugins import (
    BackendRegistry,
    BackendSpec,
    builtin,
    make_singleton,
)

__all__ = [
    "BUILTIN_BACKENDS",
    "registry",
]

logger = getLogger(__name__)


# One process-wide registry owns host services for every backend activation.
_host_capability_registry = make_singleton(PluginHostCapabilityRegistry)

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
#: Named ``<domain>.<vendor>`` to mirror the module layout -- which also makes
#: the two-Z3 distinction warned about above visible in the report rather than
#: buried in a docstring.
#:
#: ``facts`` and ``hexrays`` are deliberately absent: they are the IDA vendor
#: spine, not optional backends. A registry row saying "unavailable: no
#: ida_hexrays" outside IDA would be a tautology, and inside IDA they are never
#: not there.
#: ``cobra`` is deliberately absent: it ships as the separate distribution
#: ``d810-cobra`` and arrives through the ``d810.backends`` entry
#: point. Keeping a builtin row for it would mean d810's wheel carrying a
#: C++23 build of abseil, highway and cobra-core, and would pin CoBRA's version
#: to a d810 commit.
BUILTIN_BACKENDS: tuple[BackendSpec, ...] = (
    builtin("mba.z3", "d810.backends.mba.z3"),
    builtin("ast.z3", "d810.backends.ast.z3"),
    builtin("emulation.triton", "d810.backends.emulation.triton"),
    builtin("emulation.unicorn", "d810.backends.emulation.unicorn"),
    builtin("llvm", "d810.backends.llvm"),
)


#: The process-wide backend registry. Assembled here rather than in
#: ``core.plugins`` so the mechanism stays beneath the backends it serves.
registry = make_singleton(
    lambda: BackendRegistry(
        builtins=BUILTIN_BACKENDS,
        host=_host_capability_registry(),
        requirement_validator=_host_capability_registry().validate,
        host_view_factory=_host_capability_registry().view_for,
    )
)

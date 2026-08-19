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

import importlib

from d810.core import getLogger
from d810.core.plugins import (
    BackendRegistry,
    BackendSpec,
    PassImplementationCandidate,
    builtin,
    make_singleton,
)

__all__ = [
    "BUILTIN_BACKENDS",
    "load_extension_rule_for_candidate",
    "load_extension_rules",
    "registry",
]

logger = getLogger(__name__)

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
    builtin("mba.egglog", "d810.backends.mba.egglog_backend"),
    builtin("ast.z3", "d810.backends.ast.z3"),
    builtin("emulation.triton", "d810.backends.emulation.triton"),
    builtin("emulation.unicorn", "d810.backends.emulation.unicorn"),
    builtin("llvm", "d810.backends.llvm"),
)


def load_extension_rule_for_candidate(
    candidate: PassImplementationCandidate,
):
    """Find an instruction rule after its declared modules have imported.

    The optimizer layer owns the concrete ``InstructionOptimizationRule``
    registry.  Keeping this callback here lets ``d810.core.plugins`` perform
    strict activation without importing that higher layer.
    """
    # This is a deliberate composition-root adapter.  Keep the dependency
    # dynamic so the backend layer does not acquire an upward import edge (and
    # unit-test catalogue reads do not pull IDA/Hex-Rays into core).
    module = importlib.import_module(
        "d810.optimizers.microcode.instructions.handler"
    )
    return module.InstructionOptimizationRule.find(candidate.rule_name)


#: The process-wide backend registry. Assembled here rather than in
#: ``core.plugins`` so the mechanism stays beneath the backends it serves.
registry = make_singleton(
    lambda: BackendRegistry(
        builtins=BUILTIN_BACKENDS,
        registration_lookup=load_extension_rule_for_candidate,
    )
)


def load_extension_rules() -> None:
    """Import optimizer rules contributed by installed backend extensions.

    d810 loads its own rules by scanning ``d810.optimizers.__path__`` and
    letting ``Registrant`` self-register on import. That scan is path-scoped,
    so it cannot reach a rule that lives inside an installed extension package.
    Without this, an extension's backend probes ``available`` while the rule it
    ships never registers -- the pass is simply absent, which is
    indistinguishable from a pass that ran and matched nothing.

    Lives here rather than in ``d810.optimizers`` because the registry is what
    knows which extensions resolved; the optimizer package only knows how to
    walk its own tree.

    Only backends that resolved contribute paths (see
    ``BackendRegistry.rule_modules``), so a rule whose binding is missing is
    never registered rather than registered-and-failing.

    A rule that cannot import must not take the rest of the optimizer catalogue
    with it: an extension is optional by construction, and d810 has to start
    without it.
    """
    for module_name in registry().rule_modules():
        try:
            importlib.import_module(module_name)
        except Exception:
            logger.exception(
                "extension rule module failed to import, rule not registered: %s",
                module_name,
            )
        else:
            logger.info("extension rule module loaded: %s", module_name)

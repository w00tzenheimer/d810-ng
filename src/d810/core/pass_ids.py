"""The pass-id vocabulary: stable names for d810's config-v2 passes.

A pass id is a *name in a shared vocabulary* rather than an implementation
detail. Three parties spell it independently:

* d810 registers a pass under it and derives ``allowed_rule_names`` from it;
* a project's config JSON selects passes by it;
* an out-of-tree extension binds a rule to it through its manifest's
  ``implements`` mapping.

As bare literals that vocabulary drifted -- ``"mba-simplify"`` was written out
twice in two modules, so a typo in either would produce a pass that registers,
accepts config, and never runs. Naming them once here makes that a NameError at
import instead of silence at runtime.

Lives in ``core`` because :meth:`d810.core.plugins.BackendRegistry.
implementation_for` is typed with it, and ``core`` is the bottom layer -- it may
not import ``d810.passes``. The pass modules alias their existing ``*_PASS_ID``
constants to these members, so this is the definition and they are the
back-references.

``StrEnum``, not ``Enum``: members must *be* their wire value. Extension
manifests are plain dicts keyed by plain strings -- deliberately, so that
installing an extension does not require importing d810 -- and config JSON
carries raw strings. Because ``StrEnum`` members hash and compare as ``str``,
``manifest.implements.get(PassId.MBA_SOLVE)`` finds ``{"mba-solve": ...}``
without either side knowing about the other.
"""

from __future__ import annotations

import enum

__all__ = ["PassId"]


class PassId(enum.StrEnum):
    """Stable identifiers for the config-v2 passes d810 ships.

    Values are the on-the-wire strings. They appear in shipped project configs
    and in third-party extension manifests, so a value is an API commitment:
    changing one silently orphans every config that names it, and every
    extension bound to it.
    """

    #: Pattern-matched MBA identities (d810's own transform catalogue).
    MBA_SIMPLIFY = "mba-simplify"

    #: Solver-derived MBA simplification. d810 defines the pass; the solving
    #: itself arrives from an extension that declares this id in ``implements``.
    MBA_SOLVE = "mba-solve"

    #: Bounded Egglog extraction with a proof-gated live hook implementation.
    MBA_EGGLOG = "mba-egglog"

    #: Exact 64-bit compiler idiom lifting after bounded MBA simplification.
    ROTATE_IDIOM_RECOVERY = "rotate-idiom-recovery"

    #: Constant folding / expression-level constant simplification.
    CONSTANT_SIMPLIFICATION = "constant-simplification"

    #: Residual-dispatcher cleanup for the simple-flattening family.
    SIMPLE_FLATTENING_CLEANUP = "simple-flattening-cleanup-unflattener"

    # The state-machine CFF spine. These five are one ordered sequence rather
    # than five independent passes: the runtime rejects a config that contains
    # some but not all of them, in this order.
    #
    # Note the values use underscores where the passes above use hyphens. That
    # inconsistency predates this enum and is preserved deliberately -- these
    # strings appear in shipped project configs, so normalising the spelling
    # would orphan every config naming them.
    RECOVER_DISPATCHER = "recover_dispatcher"
    RECOVER_STATE_TRANSITIONS = "recover_state_transitions"
    PLAN_SEMANTIC_REGIONS = "plan_semantic_regions"
    LOWER_STATE_MACHINE = "lower_state_machine"
    CLEANUP_RESIDUAL_DISPATCHER = "cleanup_residual_dispatcher"

    def __repr__(self) -> str:
        """Render as the underlying string, not ``<PassId.X: 'x'>``.

        ``StrEnum`` gives members ``str``'s ``__str__`` but keeps ``Enum``'s
        ``__repr__``. Existing messages interpolate pass ids with ``!r``::

            f"expected {CONSTANT_SIMPLIFICATION_PASS_ID!r}, got {config.pass_id!r}"

        so aliasing those constants to members turned

            expected 'constant-simplification', got 'mba-solve'

        into a line whose two halves disagree -- the left an enum repr, the
        right still a raw string from config. The same leak reaches any
        container interpolation, since ``f"{list(...)}"`` formats elements with
        ``repr``.

        Overriding it keeps a member substitutable for its value in *every*
        formatting context, which is the whole premise of ``StrEnum`` here.
        ``.name`` and ``.value`` are untouched, so the symbolic half survives.
        """
        return repr(self.value)

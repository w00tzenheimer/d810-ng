"""Back-compat shim. Canonical home: ``d810.backends.hexrays.evidence.bst_analysis``.

Relocated in the LS6 bst-cluster split (Landing Sequence step 6 / ticket
d81-1w16): the live-mba BST evidence walker (which duck-types Hex-Rays
``mba``/``mop``/``minsn`` objects and builds the ``MicrocodeEvalSeams`` for
the portable ``d810.analyses.value_flow.state_write`` core) moved into the
Hex-Rays backend evidence subtree.

This module aliases the old ``d810.recon.flow.bst_analysis`` path to the
canonical module so every existing importer keeps working unchanged --
including the private helpers consumers reach into
(``_forward_eval_insn``, ``_detect_state_var_stkoff``,
``_dump_dispatcher_node``, ``_find_pre_header_state``, ``_walk_handler_chain``,
``_get_mop_const_value``) -- until they are repointed (LS6 S8/S9).

The static import edge below is ``recon -> backends`` (downward, allowed);
the relocated module imports only ``analyses.*`` and the Hex-Rays runtime, so
there is no ``backends -> recon`` back-edge.  Do not add new code here.
"""
from __future__ import annotations

import sys

from d810.backends.hexrays.evidence import bst_analysis as _impl

# Alias the old dotted path to the relocated module so attribute access and
# ``from d810.recon.flow.bst_analysis import <anything>`` (public or private)
# resolve to the canonical implementation during the migration window.
sys.modules[__name__] = _impl

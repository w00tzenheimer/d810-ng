"""Hex-Rays evidence adapters (live-mba-bound analysis services).

``d810.backends.hexrays.evidence`` hosts live-mba evidence walkers and
constant-resolution services that duck-type Hex-Rays ``mba`` / ``mblock`` /
``mop`` / ``minsn`` objects.  Unlike the portable ``d810.analyses`` layer,
modules here MAY import ``ida_hexrays`` / ``idaapi`` and the Hex-Rays runtime
(``d810.backends.hexrays.bst_runtime``); they are the vendor implementation
behind the portable analysis vocabulary.

Relocated from ``d810.recon.flow`` in the LS6 bst-cluster split (Landing
Sequence step 6 / ticket d81-1w16): the pure BST graph models live in
``d810.analyses.control_flow`` and the pure constant-folding core in
``d810.analyses.value_flow``; the live walker that builds the seams and
delegates to them lives here.
"""

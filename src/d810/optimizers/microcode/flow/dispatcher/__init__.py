"""Live-IDA dispatcher analysis adapters for microcode optimizers.

Modules in this subpackage are the live boundary around the pure
recon analyzer at ``d810.recon.flow.dispatcher_analysis``.  They
own:

* The mba-lift call (``d810.hexrays.mutation.ir_translator.lift``).
* Cross-maturity state preservation for the dispatcher cache.
* Live-IDA features that have no portable analog -- Unicorn-backed
  emulation validation, frame-size lookup, processor detection.

Layering: this subpackage lives in ``d810.optimizers`` (layer 3),
which is allowed to import ``d810.recon`` (5), ``d810.backends``
(6), and ``d810.hexrays`` (8) by the layered-architecture contract.
The pure recon analyzer cannot be hosted in ``d810.hexrays`` because
hexrays is BELOW recon in the layer stack and an upward import is
forbidden -- so the live adapter lives here instead.

Direction: ``d810.optimizers.microcode.flow.dispatcher`` ->
``d810.recon.flow.*`` (pure analyzer + facts) and ->
``d810.hexrays.mutation`` (lift), never the reverse.
"""

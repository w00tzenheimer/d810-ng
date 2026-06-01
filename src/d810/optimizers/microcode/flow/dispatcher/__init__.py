"""Live-IDA dispatcher analysis adapters for microcode optimizers.

Modules in this subpackage are the live boundary around the pure
recon analyzer at ``d810.analyses.control_flow.dispatcher_analysis``.  They
own:

* The mba-lift call (``d810.hexrays.mutation.ir_translator.lift``).
* Cross-maturity state preservation for the dispatcher cache.
* Live-IDA features that have no portable analog -- Unicorn-backed
  emulation validation, frame-size lookup, processor detection.

Layering: this subpackage lives in ``d810.optimizers`` (layer 3),
which is allowed to import the portable-core ``d810.analyses`` /
``d810.transforms`` packages, ``d810.backends`` (6), and
``d810.hexrays`` (8) by the layered-architecture contract. The pure
analyzer is hosted in portable-core (``d810.analyses.control_flow``),
which must stay hexrays-agnostic -- so the live adapter lives here
instead.

Direction: ``d810.optimizers.microcode.flow.dispatcher`` ->
``d810.analyses.control_flow.*`` (pure analyzer + facts) and ->
``d810.hexrays.mutation`` (lift), never the reverse.
"""

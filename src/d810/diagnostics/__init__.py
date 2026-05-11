"""Post-hoc diagnostic CLI, queries, and report formatters.

This package is the **high-level** companion to :mod:`d810.core.diag`:

- :mod:`d810.core.diag` is the **capture-time** substrate -- schema,
  snapshot writers, mba/cfg provenance serializers, ``get_diag_db()`` and
  related session-lifecycle hooks. Lower layers (``cfg``, ``recon``,
  ``optimizers``, ``hexrays``) call into it during decompilation.
- :mod:`d810.diagnostics` (this package) is the **post-hoc** side -- DB
  queries, log parsers, report formatters, and the ``python -m
  d810.diagnostics`` CLI. It may freely import from ``cfg``, ``recon``,
  and ``optimizers`` because it sits **above** them in the layered
  architecture (see ``.importlinter``).

This split keeps capture-time code reachable from low-layer runtime modules
without inverting the dependency graph. Reach for :mod:`d810.diagnostics`
when you need to consume a diag SQLite or a ``d810.log`` after the fact.
"""

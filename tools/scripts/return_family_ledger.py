#!/usr/bin/env python3
"""Compatibility deprecation stub.

Migrated to ``d810.diagnostics`` -- see ``docs/debug-tooling-migration.md``.
This script's legacy CLI took a positional dump file and auto-located the
matching diag SQLite, which does not map cleanly to the new
``--db`` / ``--dump`` argument shape, so this stub fails rather than
silently translating arguments.

Use one of:

    ./tools/d810cli.py returns
    PYTHONPATH=src python -m d810.diagnostics return-ledger --db DB [--dump DUMP]

The full implementation now lives in ``src/d810/diagnostics/return_ledger.py``
with unit tests under ``tests/unit/diagnostics/test_return_ledger.py``.
"""
from __future__ import annotations

import sys

_MESSAGE = """\
[deprecated] tools/scripts/return_family_ledger.py was migrated to
``d810.diagnostics``. The legacy CLI (positional dump file + auto DB
discovery) does not map cleanly to the new command, so this stub fails
to avoid silently running stale logic.

Use one of:

  ./tools/d810cli.py returns
  PYTHONPATH=src python -m d810.diagnostics return-ledger --db DB [--dump DUMP]

See docs/debug-tooling-migration.md for the full migration table.
"""

print(_MESSAGE, file=sys.stderr)
sys.exit(2)

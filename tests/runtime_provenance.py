"""Provenance fields every performance receipt must record.

The runner exports the identity of the container that produced a measurement
and, for a remote run, the offset of the engine clock those measurements were
timed against. A receipt without the offset cannot be compared against another
host's, so the fields are assembled here once and consumed by every writer.
"""

from __future__ import annotations

import os
from d810.core.typing import Mapping

__all__ = ["MISSING_PROVENANCE", "runtime_provenance"]

#: A field the environment did not supply. Never the empty string: an empty
#: value in a receipt reads as "measured and found to be nothing".
MISSING_PROVENANCE = "n/a"


def runtime_provenance(
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the runtime provenance fields, with placeholders for absences.

    ``engine_clock_offset_seconds`` is set only by a ``--remote`` run; a local
    run has no engine clock of its own, so it records the placeholder.

    >>> runtime_provenance({})["engine_clock_offset_seconds"]
    'n/a'
    >>> runtime_provenance({"D810_TEST_ENGINE_CLOCK_OFFSET": "-3"})[
    ...     "engine_clock_offset_seconds"
    ... ]
    '-3'
    >>> runtime_provenance({"D810_TEST_ENGINE_CLOCK_OFFSET": ""})[
    ...     "engine_clock_offset_seconds"
    ... ]
    'n/a'
    """
    source = os.environ if environ is None else environ
    return {
        "runtime_image": source.get("D810_TEST_RUNTIME_IMAGE") or MISSING_PROVENANCE,
        "runtime_image_id": (
            source.get("D810_TEST_RUNTIME_IMAGE_ID") or MISSING_PROVENANCE
        ),
        "engine_clock_offset_seconds": (
            source.get("D810_TEST_ENGINE_CLOCK_OFFSET") or MISSING_PROVENANCE
        ),
    }

"""Provenance fields every performance receipt must record.

The runner exports the identity of the container that produced a measurement,
the identity of the d810-cobra artifact that solved inside it, and, for a
remote run, the offset of the engine clock those measurements were timed
against. A receipt without the offset cannot be compared against another
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

    The ``cobra_*`` fields are set only when a PUBLISHED d810-cobra wheel is
    installed -- baked into the image or mounted explicitly. A source-built
    backend has no published identity, and inventing one would make two
    different artifacts look like the same measurement, so it records the
    placeholder.

    >>> runtime_provenance({})["cobra_wheel_sha256"]
    'n/a'
    >>> runtime_provenance({"D810_TEST_COBRA_SOURCE_MODE": "baked"})[
    ...     "cobra_source_mode"
    ... ]
    'baked'

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
        "cobra_source_mode": (
            source.get("D810_TEST_COBRA_SOURCE_MODE") or MISSING_PROVENANCE
        ),
        "cobra_wheel_sha256": (
            source.get("D810_TEST_COBRA_WHEEL_SHA256") or MISSING_PROVENANCE
        ),
        "cobra_tag_commit": (
            source.get("D810_TEST_COBRA_TAG_COMMIT") or MISSING_PROVENANCE
        ),
    }

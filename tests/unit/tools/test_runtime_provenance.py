"""The provenance fields every performance receipt records."""

from __future__ import annotations

import json

import pytest

from tests.runtime_provenance import MISSING_PROVENANCE, runtime_provenance

REMOTE_ENVIRONMENT = {
    "D810_TEST_RUNTIME_IMAGE": "runtime-image",
    "D810_TEST_RUNTIME_IMAGE_ID": "sha256:" + "1f" * 32,
    "D810_TEST_ENGINE_CLOCK_OFFSET": "-3",
}


def test_a_remote_receipt_records_the_measured_engine_clock_offset() -> None:
    """Every duration in the run was timed against that clock."""
    provenance = runtime_provenance(REMOTE_ENVIRONMENT)

    assert provenance["engine_clock_offset_seconds"] == "-3"
    assert provenance["runtime_image_id"] == REMOTE_ENVIRONMENT[
        "D810_TEST_RUNTIME_IMAGE_ID"
    ]
    # the receipt is JSON on one side and markdown on the other; both need it
    assert "engine_clock_offset_seconds" in json.loads(json.dumps(provenance))


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {"D810_TEST_ENGINE_CLOCK_OFFSET": ""},
    ],
)
def test_a_local_receipt_records_a_placeholder_not_an_empty_field(
    environment: dict[str, str],
) -> None:
    """An empty value reads as 'measured and found to be nothing'."""
    provenance = runtime_provenance(environment)

    assert provenance["engine_clock_offset_seconds"] == MISSING_PROVENANCE
    assert MISSING_PROVENANCE == "n/a"
    assert "" not in provenance.values()


def test_every_provenance_field_has_a_placeholder() -> None:
    provenance = runtime_provenance({})

    assert set(provenance) == {
        "runtime_image",
        "runtime_image_id",
        "engine_clock_offset_seconds",
        "cobra_source_mode",
        "cobra_wheel_sha256",
        "cobra_tag_commit",
    }
    assert set(provenance.values()) == {MISSING_PROVENANCE}


def test_a_positive_offset_survives_unchanged() -> None:
    assert (
        runtime_provenance({"D810_TEST_ENGINE_CLOCK_OFFSET": "755"})[
            "engine_clock_offset_seconds"
        ]
        == "755"
    )


PUBLISHED_WHEEL_SHA256 = (
    "2c85ffe14a1f3c1d2b750790332a7c0a5e911b35f7fc041ebedcd6532382c63c"
)
TAG_COMMIT = "73b405c106d78e1fdc7576b217de39b7dcd0ddb3"


def test_a_baked_receipt_records_the_published_wheel_and_tag() -> None:
    """The distribution version is not an identity: 0.1.4 shipped two manifests."""
    provenance = runtime_provenance(
        {
            "D810_TEST_COBRA_SOURCE_MODE": "baked",
            "D810_TEST_COBRA_WHEEL_SHA256": PUBLISHED_WHEEL_SHA256,
            "D810_TEST_COBRA_TAG_COMMIT": TAG_COMMIT,
        }
    )

    assert provenance["cobra_source_mode"] == "baked"
    assert provenance["cobra_wheel_sha256"] == PUBLISHED_WHEEL_SHA256
    assert provenance["cobra_tag_commit"] == TAG_COMMIT


def test_a_source_built_backend_records_no_fabricated_wheel_identity() -> None:
    provenance = runtime_provenance({"D810_TEST_RUNTIME_IMAGE": "runtime-image"})

    assert provenance["cobra_wheel_sha256"] == MISSING_PROVENANCE
    assert provenance["cobra_tag_commit"] == MISSING_PROVENANCE
    assert provenance["cobra_source_mode"] == MISSING_PROVENANCE

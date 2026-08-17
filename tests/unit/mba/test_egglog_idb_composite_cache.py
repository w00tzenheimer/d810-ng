from __future__ import annotations

from copy import deepcopy

import pytest

from d810.mba.egglog_composite_rewrite import (
    ActiveSemantics,
    EgglogCompositeRewrite,
)
from d810.mba.typed_term import TypedBvTerm


CATALOGUE_DIGEST = "a" * 64
PROFILE_DIGEST = "b" * 64


def leaf(name: str, *, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("register", name))


def const(value: int, *, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def binary(
    operation: str, left: TypedBvTerm, right: TypedBvTerm
) -> TypedBvTerm:
    return TypedBvTerm(operation, left.width, children=(left, right))


@pytest.fixture
def semantics() -> ActiveSemantics:
    return ActiveSemantics(
        canonicalizer_version=1,
        catalogue_digest=CATALOGUE_DIGEST,
        profile_digest=PROFILE_DIGEST,
        egglog_version="13.2.0",
        proof_mode="shadow",
        active_rule_names=(("add", "R"),),
    )


def make_rewrite(
    semantics: ActiveSemantics,
    index: int,
    *,
    profile_digest: str | None = None,
) -> EgglogCompositeRewrite:
    active = semantics
    if profile_digest is not None:
        active = ActiveSemantics(
            canonicalizer_version=semantics.canonicalizer_version,
            catalogue_digest=semantics.catalogue_digest,
            profile_digest=profile_digest,
            egglog_version=semantics.egglog_version,
            proof_mode=semantics.proof_mode,
            active_rule_names=semantics.active_rule_names,
        )
    source_leaf = leaf(f"x{index}")
    source = binary(
        "add",
        binary("add", source_leaf, source_leaf),
        source_leaf,
    )
    output = binary("mul", const(index + 3), source_leaf)
    return EgglogCompositeRewrite.from_extraction(
        input_term=source,
        output_term=output,
        derivation_trace=(("add", "R", ()),),
        semantics=active,
    )


def cached(
    rewrite: EgglogCompositeRewrite,
    *,
    created_sequence: int,
    last_used_sequence: int,
) -> EgglogCompositeRewrite:
    return rewrite.with_sequences(
        created_sequence=created_sequence,
        last_used_sequence=last_used_sequence,
    )


@pytest.fixture
def rewrites(semantics: ActiveSemantics) -> tuple[EgglogCompositeRewrite, ...]:
    return tuple(
        make_rewrite(
            semantics,
            index,
            profile_digest=(PROFILE_DIGEST if index == 0 else chr(ord("b") + index) * 64),
        )
        for index in range(3)
    )


@pytest.fixture
def same_bucket_rewrites(
    semantics: ActiveSemantics,
) -> tuple[EgglogCompositeRewrite, ...]:
    return (make_rewrite(semantics, 0), make_rewrite(semantics, 1))


@pytest.fixture
def fake_store() -> dict[str, object]:
    return {}


def test_empty_cache_loads_no_rewrites(fake_store: dict[str, object]) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    assert cache.get(("a" * 64, "b" * 64, 1, "13.2.0", "shadow", 32, "add", 2)) == ()
    assert fake_store == {}


def test_cache_round_trip_uses_dedicated_manifest_and_entry_keys(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(rewrites[0])

    assert set(fake_store) == {"manifest", f"entry:{rewrites[0].template_id}"}
    assert cache.get(rewrites[0].bucket_key) == (
        cached(rewrites[0], created_sequence=1, last_used_sequence=2),
    )


def test_store_persists_cache_owned_sequences_in_payload_and_manifest(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(rewrites[0])

    payload = fake_store[f"entry:{rewrites[0].template_id}"]
    manifest = fake_store["manifest"]
    assert isinstance(payload, dict)
    assert isinstance(manifest, dict)
    metadata = manifest["entries"][0]
    assert payload["created_sequence"] == metadata["created_sequence"] == 1
    assert payload["last_used_sequence"] == metadata["last_used_sequence"] == 1


def test_cache_accounts_canonical_uncompressed_entry_bytes(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(rewrites[0])

    manifest = fake_store["manifest"]
    assert isinstance(manifest, dict)
    stored = cached(rewrites[0], created_sequence=1, last_used_sequence=1)
    assert manifest["total_bytes"] == len(stored.to_json().encode("utf-8"))


def test_get_advances_payload_manifest_and_byte_accounting_together(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(rewrites[0])
    result = cache.get(rewrites[0].bucket_key)

    expected = cached(rewrites[0], created_sequence=1, last_used_sequence=2)
    assert result == (expected,)
    payload = fake_store[f"entry:{rewrites[0].template_id}"]
    manifest = fake_store["manifest"]
    assert isinstance(payload, dict)
    assert isinstance(manifest, dict)
    metadata = manifest["entries"][0]
    assert payload["created_sequence"] == metadata["created_sequence"] == 1
    assert payload["last_used_sequence"] == metadata["last_used_sequence"] == 2
    assert metadata["byte_size"] == len(expected.to_json().encode("utf-8"))
    assert manifest["total_bytes"] == metadata["byte_size"]


def test_cache_updates_lru_before_entry_eviction(
    fake_store: dict[str, object],
    semantics: ActiveSemantics,
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store, max_entries=2)
    cache.store(rewrites[0])
    cache.store(rewrites[1])
    assert cache.get(rewrites[0].bucket_key) == (
        cached(rewrites[0], created_sequence=1, last_used_sequence=3),
    )

    # A new rewrite in a third bucket makes the untouched second entry the
    # oldest one, while the first entry was just used.
    replacement = make_rewrite(semantics, 3, profile_digest="e" * 64)
    cache.store(replacement)

    assert cache.get(rewrites[0].bucket_key) == (
        cached(rewrites[0], created_sequence=1, last_used_sequence=5),
    )
    assert cache.get(rewrites[1].bucket_key) == ()
    assert cache.get(replacement.bucket_key) == (
        cached(replacement, created_sequence=4, last_used_sequence=6),
    )


def test_cache_evicts_oldest_entry_before_entry_limit(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store, max_entries=2, max_bytes=2_097_152)
    for rewrite in rewrites:
        cache.store(rewrite)

    assert cache.get(rewrites[0].bucket_key) == ()
    assert cache.get(rewrites[1].bucket_key) == (
        cached(rewrites[1], created_sequence=2, last_used_sequence=4),
    )
    assert cache.get(rewrites[2].bucket_key) == (
        cached(rewrites[2], created_sequence=3, last_used_sequence=5),
    )


def test_cache_evicts_oldest_entry_before_byte_limit(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    sizes = [
        len(
            cached(
                rewrite,
                created_sequence=index + 1,
                last_used_sequence=index + 1,
            )
            .to_json()
            .encode("utf-8")
        )
        for index, rewrite in enumerate(rewrites)
    ]
    cache = EgglogIdbCompositeCache(
        fake_store,
        max_entries=256,
        max_bytes=sizes[0] + sizes[1] - 1,
    )
    cache.store(rewrites[0])
    cache.store(rewrites[1])

    assert cache.get(rewrites[0].bucket_key) == ()
    assert cache.get(rewrites[1].bucket_key) == (
        cached(rewrites[1], created_sequence=2, last_used_sequence=3),
    )


def test_sequence_digit_growth_evicts_updated_entry_without_overflow(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    rewrite = rewrites[0]
    sequence_nine = cached(rewrite, created_sequence=9, last_used_sequence=9)
    sequence_ten = cached(rewrite, created_sequence=9, last_used_sequence=10)
    size_nine = len(sequence_nine.to_json().encode("utf-8"))
    assert len(sequence_ten.to_json().encode("utf-8")) > size_nine
    fake_store[f"entry:{rewrite.template_id}"] = sequence_nine.to_dict()
    fake_store["manifest"] = {
        "schema_version": 1,
        "sequence": 9,
        "total_bytes": size_nine,
        "entries": [
            {
                "template_id": rewrite.template_id,
                "bucket_key": list(rewrite.bucket_key),
                "byte_size": size_nine,
                "created_sequence": 9,
                "last_used_sequence": 9,
            }
        ],
    }
    cache = EgglogIdbCompositeCache(fake_store, max_bytes=size_nine)

    assert cache.get(rewrite.bucket_key) == ()
    manifest = fake_store["manifest"]
    assert isinstance(manifest, dict)
    assert manifest["sequence"] == 10
    assert manifest["entries"] == []
    assert manifest["total_bytes"] == 0
    assert f"entry:{rewrite.template_id}" not in fake_store


def test_corrupt_manifest_clears_only_this_feature_node_state(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(rewrites[0])
    fake_store["manifest"] = {"schema_version": 999}
    fake_store["unrelated"] = {"keep": True}

    assert cache.get(rewrites[0].bucket_key) == ()
    assert "manifest" not in fake_store
    assert f"entry:{rewrites[0].template_id}" not in fake_store
    assert fake_store["unrelated"] == {"keep": True}


def test_lookup_reports_malformed_state_while_get_stays_compatible(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(rewrites[0])
    fake_store[f"entry:{rewrites[0].template_id}"] = {"corrupt": True}

    result = cache.lookup(rewrites[0].bucket_key)
    assert result.status == "malformed"
    assert result.rewrites == ()
    assert cache.get(rewrites[0].bucket_key) == ()


@pytest.mark.parametrize(
    "status, rewrites",
    [("unknown", ()), ("hit", []), ("hit", (object(),))],
)
def test_lookup_result_rejects_unknown_status_or_rewrite_shape(
    status: str, rewrites: object
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import (
        EgglogCompositeCacheLookup,
    )

    with pytest.raises(ValueError):
        EgglogCompositeCacheLookup(status, rewrites)  # type: ignore[arg-type]


def test_manifest_over_entry_bound_is_cleared(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    unrestricted = EgglogIdbCompositeCache(fake_store)
    unrestricted.store(rewrites[0])
    unrestricted.store(rewrites[1])
    bounded = EgglogIdbCompositeCache(fake_store, max_entries=1)

    assert bounded.get(rewrites[0].bucket_key) == ()
    assert "manifest" not in fake_store
    assert not any(key.startswith("entry:") for key in fake_store)


def test_manifest_over_byte_bound_is_cleared(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    unrestricted = EgglogIdbCompositeCache(fake_store)
    unrestricted.store(rewrites[0])
    size = len(rewrites[0].to_json().encode("utf-8"))
    bounded = EgglogIdbCompositeCache(fake_store, max_bytes=size - 1)

    assert bounded.get(rewrites[0].bucket_key) == ()
    assert "manifest" not in fake_store
    assert not any(key.startswith("entry:") for key in fake_store)


def test_corrupt_entry_removes_only_that_entry(
    fake_store: dict[str, object],
    same_bucket_rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(same_bucket_rewrites[0])
    cache.store(same_bucket_rewrites[1])
    fake_store[f"entry:{same_bucket_rewrites[0].template_id}"] = {"broken": object()}

    assert cache.get(same_bucket_rewrites[0].bucket_key) == (
        cached(same_bucket_rewrites[1], created_sequence=2, last_used_sequence=3),
    )
    assert f"entry:{same_bucket_rewrites[0].template_id}" not in fake_store


def test_sequence_mismatch_removes_only_that_entry(
    fake_store: dict[str, object],
    same_bucket_rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(same_bucket_rewrites[0])
    cache.store(same_bucket_rewrites[1])
    fake_store[f"entry:{same_bucket_rewrites[0].template_id}"] = cached(
        same_bucket_rewrites[0], created_sequence=1, last_used_sequence=99
    ).to_dict()

    assert cache.get(same_bucket_rewrites[0].bucket_key) == (
        cached(same_bucket_rewrites[1], created_sequence=2, last_used_sequence=3),
    )
    assert f"entry:{same_bucket_rewrites[0].template_id}" not in fake_store


def test_stale_semantic_fingerprint_is_an_exact_miss(
    fake_store: dict[str, object],
    semantics: ActiveSemantics,
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    current = make_rewrite(semantics, 0)
    stale = make_rewrite(semantics, 0, profile_digest="c" * 64)
    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(stale)

    assert cache.get(current.bucket_key) == ()
    assert cache.get(stale.bucket_key) == (
        cached(stale, created_sequence=1, last_used_sequence=2),
    )


def test_schema_mismatch_in_one_entry_does_not_clear_siblings(
    fake_store: dict[str, object],
    same_bucket_rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(same_bucket_rewrites[0])
    cache.store(same_bucket_rewrites[1])
    broken = deepcopy(same_bucket_rewrites[0].to_dict())
    broken["schema_version"] = 99
    fake_store[f"entry:{same_bucket_rewrites[0].template_id}"] = broken

    assert cache.get(same_bucket_rewrites[0].bucket_key) == (
        cached(same_bucket_rewrites[1], created_sequence=2, last_used_sequence=3),
    )


def test_missing_entry_payload_removes_metadata_only(
    fake_store: dict[str, object],
    same_bucket_rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(same_bucket_rewrites[0])
    cache.store(same_bucket_rewrites[1])
    del fake_store[f"entry:{same_bucket_rewrites[0].template_id}"]

    assert cache.get(same_bucket_rewrites[0].bucket_key) == (
        cached(same_bucket_rewrites[1], created_sequence=2, last_used_sequence=3),
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_entries": 0},
        {"max_entries": -1},
        {"max_entries": True},
        {"max_bytes": 0},
        {"max_bytes": -1},
        {"max_bytes": False},
    ],
)
def test_cache_rejects_non_positive_or_boolean_bounds(
    fake_store: dict[str, object], kwargs: dict[str, object]
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    with pytest.raises(ValueError, match="positive integer"):
        EgglogIdbCompositeCache(fake_store, **kwargs)


class FailingStore(dict[str, object]):
    def __init__(self, *args: object, fail_keys: set[str] | None = None) -> None:
        super().__init__(*args)
        self.fail_keys = set() if fail_keys is None else set(fail_keys)

    def __setitem__(self, key: str, value: object) -> None:
        if key in self.fail_keys:
            raise OSError(f"write blocked for {key}")
        super().__setitem__(key, value)


def test_cache_write_failure_does_not_leave_a_partial_entry(
    semantics: ActiveSemantics,
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    store: FailingStore = FailingStore(fail_keys={"manifest"})
    cache = EgglogIdbCompositeCache(store)
    rewrite = make_rewrite(semantics, 0)

    with pytest.raises(RuntimeError, match="cache write failed"):
        cache.store(rewrite)

    assert store == {}


def test_cache_payload_write_failure_restores_previous_state(
    semantics: ActiveSemantics,
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    store = FailingStore()
    cache = EgglogIdbCompositeCache(store)
    first = make_rewrite(semantics, 0)
    second = make_rewrite(semantics, 1, profile_digest="c" * 64)
    cache.store(first)
    before = deepcopy(store)
    store.fail_keys.add(f"entry:{second.template_id}")

    with pytest.raises(RuntimeError, match="cache write failed"):
        cache.store(second)

    assert store == before


def test_cache_get_payload_write_failure_returns_previous_state(
    semantics: ActiveSemantics,
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    store = FailingStore()
    cache = EgglogIdbCompositeCache(store)
    rewrite = make_rewrite(semantics, 0)
    cache.store(rewrite)
    before = deepcopy(store)
    store.fail_keys.add(f"entry:{rewrite.template_id}")

    assert cache.get(rewrite.bucket_key) == (
        cached(rewrite, created_sequence=1, last_used_sequence=1),
    )
    assert store == before

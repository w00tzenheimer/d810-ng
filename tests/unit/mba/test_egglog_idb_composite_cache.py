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
    assert cache.get(rewrites[0].bucket_key) == (rewrites[0],)


def test_cache_accounts_canonical_uncompressed_entry_bytes(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(rewrites[0])

    manifest = fake_store["manifest"]
    assert isinstance(manifest, dict)
    assert manifest["total_bytes"] == len(rewrites[0].to_json().encode("utf-8"))


def test_cache_updates_lru_before_entry_eviction(
    fake_store: dict[str, object],
    semantics: ActiveSemantics,
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store, max_entries=2)
    cache.store(rewrites[0])
    cache.store(rewrites[1])
    assert cache.get(rewrites[0].bucket_key) == (rewrites[0],)

    # A new rewrite in a third bucket makes the untouched second entry the
    # oldest one, while the first entry was just used.
    replacement = make_rewrite(semantics, 3, profile_digest="e" * 64)
    cache.store(replacement)

    assert cache.get(rewrites[0].bucket_key) == (rewrites[0],)
    assert cache.get(rewrites[1].bucket_key) == ()
    assert cache.get(replacement.bucket_key) == (replacement,)


def test_cache_evicts_oldest_entry_before_entry_limit(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store, max_entries=2, max_bytes=2_097_152)
    for rewrite in rewrites:
        cache.store(rewrite)

    assert cache.get(rewrites[0].bucket_key) == ()
    assert cache.get(rewrites[1].bucket_key) == (rewrites[1],)
    assert cache.get(rewrites[2].bucket_key) == (rewrites[2],)


def test_cache_evicts_oldest_entry_before_byte_limit(
    fake_store: dict[str, object],
    rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    sizes = [len(rewrite.to_json().encode("utf-8")) for rewrite in rewrites]
    cache = EgglogIdbCompositeCache(
        fake_store,
        max_entries=256,
        max_bytes=sizes[0] + sizes[1] - 1,
    )
    cache.store(rewrites[0])
    cache.store(rewrites[1])

    assert cache.get(rewrites[0].bucket_key) == ()
    assert cache.get(rewrites[1].bucket_key) == (rewrites[1],)


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

    assert cache.get(same_bucket_rewrites[0].bucket_key) == (same_bucket_rewrites[1],)
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
    assert cache.get(stale.bucket_key) == (stale,)


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

    assert cache.get(same_bucket_rewrites[0].bucket_key) == (same_bucket_rewrites[1],)


def test_missing_entry_payload_removes_metadata_only(
    fake_store: dict[str, object],
    same_bucket_rewrites: tuple[EgglogCompositeRewrite, ...],
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    cache = EgglogIdbCompositeCache(fake_store)
    cache.store(same_bucket_rewrites[0])
    cache.store(same_bucket_rewrites[1])
    del fake_store[f"entry:{same_bucket_rewrites[0].template_id}"]

    assert cache.get(same_bucket_rewrites[0].bucket_key) == (same_bucket_rewrites[1],)


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
    def __setitem__(self, key: str, value: object) -> None:
        if key == "manifest":
            raise OSError("disk full")
        super().__setitem__(key, value)


def test_cache_write_failure_does_not_leave_a_partial_entry(
    semantics: ActiveSemantics,
) -> None:
    from d810.backends.mba.egglog_idb_composite_cache import EgglogIdbCompositeCache

    store: FailingStore = FailingStore()
    cache = EgglogIdbCompositeCache(store)
    rewrite = make_rewrite(semantics, 0)

    with pytest.raises(RuntimeError, match="cache write failed"):
        cache.store(rewrite)

    assert store == {}

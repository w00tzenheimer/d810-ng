"""Immutable analysis reuse must not turn into mutable semantic reuse."""

import dis
import gc
import os
import weakref
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import subprocess
import sys
from types import CodeType

import pytest

from d810.mba import canonical_pattern, certified_catalogue


def test_repeated_consumers_do_not_redisassemble_immutable_code(monkeypatch):
    from d810.mba import _code_analysis

    monkeypatch.setattr(_code_analysis, "CACHE_ENABLED", True)
    namespace = {"answer": 7}
    exec("def sample(): return answer", namespace)
    function = namespace["sample"]
    original = dis.get_instructions
    visits = []

    def counted(code, *args, **kwargs):
        visits.append(code)
        yield from original(code, *args, **kwargs)

    monkeypatch.setattr(dis, "get_instructions", counted)
    first = canonical_pattern._jsonable_semantics(function)
    namespace["answer"] = 9
    second = canonical_pattern._jsonable_semantics(function)
    assert first["globals"]["answer"] == 7
    assert second["globals"]["answer"] == 9
    assert certified_catalogue._referenced_global_names(function.__code__) == (
        "answer",
    )
    assert len(visits) == 1


@pytest.fixture
def cache(monkeypatch):
    from d810.mba import _code_analysis

    cache = _code_analysis.CodeAnalysisCache(capacity=2)
    monkeypatch.setattr(_code_analysis, "code_analysis_cache", cache)
    monkeypatch.setattr(_code_analysis, "CACHE_ENABLED", True)
    return cache


def test_strict_path_visits_each_instruction_and_does_not_retain(cache):
    code = compile("answer + answer", "<test>", "eval")
    instruction_count = len(list(dis.get_instructions(code)))
    for _ in range(2):
        assert cache.loaded_names(code, reuse=False) == ("answer",)
    assert cache.stats() == dict(
        hits=0,
        misses=0,
        strict=2,
        instructions=2 * instruction_count,
        failures=0,
        evictions=0,
        entries=0,
    )


def test_equal_but_distinct_code_misses_and_lru_releases_strong_reference(cache):
    first = compile("answer", "<test>", "eval")
    equal = first.replace()
    third = compile("other", "<test>", "eval")
    assert first == equal and first is not equal
    retained = weakref.ref(first)
    cache.loaded_names(first)
    cache.loaded_names(equal)
    cache.loaded_names(first)  # first is now most recently used
    cache.loaded_names(third)  # equal is evicted
    assert cache.stats()["misses"] == 3
    assert cache.stats()["evictions"] == 1
    del first
    gc.collect()
    assert retained() is not None
    cache.loaded_names(equal)  # first is now evicted
    gc.collect()
    assert retained() is None
    cache.clear()
    assert cache.stats()["entries"] == 0
    assert cache.stats()["instructions"] == 0


def test_code_replacement_changes_names_and_semantics(cache):
    namespace = {"answer": 7, "other": 13}
    exec("def sample(): return answer\ndef replacement(): return other", namespace)
    function = namespace["sample"]
    assert canonical_pattern._jsonable_semantics(function)["globals"] == {"answer": 7}
    function.__code__ = namespace["replacement"].__code__
    assert canonical_pattern._jsonable_semantics(function)["globals"] == {"other": 13}
    assert cache.stats()["misses"] == 2


def test_nested_code_stays_certificate_only_and_mutation_is_visible(cache):
    namespace = {"outer": 1, "inner": 2}
    exec("def sample():\n def nested(): return inner\n return outer", namespace)
    function = namespace["sample"]
    assert canonical_pattern._jsonable_semantics(function)["globals"] == {"outer": 1}
    assert certified_catalogue._referenced_global_names(function.__code__) == (
        "inner",
        "outer",
    )
    before = certified_catalogue._semantic_value(function)
    namespace["inner"] = 3
    after = certified_catalogue._semantic_value(function)
    assert before != after


@pytest.mark.parametrize(
    "consumer",
    [canonical_pattern._jsonable_semantics, certified_catalogue._semantic_value],
)
@pytest.mark.parametrize("mutation", ["globals", "defaults", "closure"])
def test_warm_analysis_observes_mutable_semantics(cache, consumer, mutation):
    namespace = {"answer": [1]}
    exec(
        "def factory():\n captured = [2]\n def sample(default=[3]):\n  return answer, captured, default\n return sample",
        namespace,
    )
    function = namespace["factory"]()
    before = consumer(function)
    consumer(function)  # warmed analysis
    if mutation == "globals":
        namespace["answer"].append(4)
    elif mutation == "defaults":
        function.__defaults__[0].append(4)
    else:
        function.__closure__[0].cell_contents.append(4)
    assert consumer(function) != before
    assert cache.stats()["hits"] >= 2


@pytest.mark.parametrize("mutation", ["builtins", "kwdefaults"])
def test_certificate_warm_analysis_observes_builtins_and_kwdefaults(cache, mutation):
    namespace = {"__builtins__": {"answer": 1}}
    exec("def sample(*, keyword=[2]): return answer, keyword", namespace)
    function = namespace["sample"]
    before = certified_catalogue._semantic_value(function)
    if mutation == "builtins":
        namespace["__builtins__"]["answer"] = 3
    else:
        function.__kwdefaults__["keyword"].append(3)
    assert certified_catalogue._semantic_value(function) != before
    assert cache.stats()["hits"] == 1


def test_failed_partial_analysis_is_retried_and_consumers_fail_closed(
    cache, monkeypatch
):
    namespace = {"answer": 7}
    exec("def sample(): return answer", namespace)
    function = namespace["sample"]
    original = dis.get_instructions

    def broken(code):
        yield next(original(code))
        raise ValueError("unreadable")

    monkeypatch.setattr(dis, "get_instructions", broken)
    assert canonical_pattern._jsonable_semantics(function) == {
        "callable": "opaque_code"
    }
    assert certified_catalogue._referenced_global_names(function.__code__) is None
    assert cache.stats()["entries"] == 0
    assert cache.stats()["instructions"] == 2
    assert cache.stats()["failures"] == 2
    monkeypatch.setattr(dis, "get_instructions", original)
    assert cache.loaded_names(function.__code__) == ("answer",)
    assert cache.stats()["misses"] == 3


def test_concurrent_requests_publish_one_complete_analysis(cache):
    code = compile("answer + other", "<test>", "eval")
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(cache.loaded_names, [code] * 128))
    assert results == [("answer", "other")] * 128
    assert cache.stats()["misses"] == 1
    assert cache.stats()["hits"] == 127
    assert cache.stats()["instructions"] == len(list(dis.get_instructions(code)))


def test_runtime_digest_covers_code_analysis_implementation(tmp_path, monkeypatch):
    from d810.backends.mba import runtime_semantics
    from d810.mba import _code_analysis
    import json

    package = Path(_code_analysis.__file__).parents[1]
    manifest = package / "runtime_semantics_manifest.json"
    shutil.copyfile(manifest, tmp_path / manifest.name)
    paths = json.loads(manifest.read_text())["runtime_sources"]
    for path in set(paths) | {"mba/_code_analysis.py"}:
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(package / path, destination)
    monkeypatch.setattr(runtime_semantics.resources, "files", lambda _: tmp_path)
    identity = runtime_semantics.NativeMatcherRuntimeIdentity("python", "test", "test")
    before = runtime_semantics.runtime_semantics_digest(identity)
    (tmp_path / "mba/_code_analysis.py").write_text("# altered name analysis\n")
    assert runtime_semantics.runtime_semantics_digest(identity) != before


def test_mutable_disassembly_input_is_never_cached(cache):
    namespace = {}
    exec("def sample(): return first\ndef replacement(): return second", namespace)
    function = namespace["sample"]
    assert cache.loaded_names(function) == ("first",)
    function.__code__ = namespace["replacement"].__code__
    assert cache.loaded_names(function) == ("second",)
    assert cache.stats()["entries"] == 0


@pytest.mark.parametrize(
    "setting, enabled",
    [(None, False), ("0", False), ("1", True), ("true", False), ("invalid", False)],
)
def test_fresh_process_mode_is_explicit_and_reload_observes_change(setting, enabled):
    environment = os.environ.copy()
    environment.pop("D810_CODE_ANALYSIS_CACHE", None)
    if setting is not None:
        environment["D810_CODE_ANALYSIS_CACHE"] = setting
    script = """
import importlib, os, sys
from d810.mba import _code_analysis as analysis
expected = sys.argv[1] == '1'
assert analysis.CACHE_ENABLED is expected
code = compile('answer', '<fresh-child>', 'eval')
analysis.immediate_loaded_names(code)
analysis.immediate_loaded_names(code)
assert analysis.code_analysis_cache.stats()['hits'] == int(expected)
os.environ['D810_CODE_ANALYSIS_CACHE'] = '0' if expected else '1'
assert analysis.CACHE_ENABLED is expected  # import-time configuration
importlib.reload(analysis)
assert analysis.CACHE_ENABLED is not expected
assert analysis.code_analysis_cache.stats()['entries'] == 0
analysis.immediate_loaded_names(code)
analysis.immediate_loaded_names(code)
assert analysis.code_analysis_cache.stats()['hits'] == int(not expected)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(int(enabled))],
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_mutable_proxy_cannot_spoof_immutable_code_identity(cache):
    class Proxy:
        @property
        def __class__(self):
            return CodeType

    proxy = Proxy()
    proxy.__code__ = compile("first", "<proxy>", "eval")
    assert isinstance(proxy, CodeType)
    assert cache.loaded_names(proxy) == ("first",)
    proxy.__code__ = compile("second", "<proxy>", "eval")
    assert cache.loaded_names(proxy) == ("second",)
    assert cache.stats()["entries"] == 0

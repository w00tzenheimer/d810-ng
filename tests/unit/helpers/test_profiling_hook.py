"""Unit tests for the env-gated ProfilingController hook's pure helpers.

These cover only the IDA-free logic in
``tests/system/helpers/profiling_hook.py``: label validation, nodeid
sanitising, and output-directory resolution. The IDA-dependent wiring
(``D810State``/``D810Manager``) is exercised by system tests, not here.
"""

from __future__ import annotations

import pathlib

import pytest

from tests.system.helpers.profiling_hook import (
    DEFAULT_PROFILE_LABEL,
    profiling_hook_enabled,
    resolve_profile_output_dir,
    sanitize_nodeid,
    validate_profile_label,
)


class TestProfilingHookEnabled:
    def test_none_is_disabled(self):
        assert profiling_hook_enabled(None) is False

    def test_empty_string_is_disabled(self):
        assert profiling_hook_enabled("") is False

    def test_on_is_enabled(self):
        assert profiling_hook_enabled("on") is True

    def test_off_is_disabled(self):
        assert profiling_hook_enabled("off") is False

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError, match="D810_PROFILE_CONTROLLER"):
            profiling_hook_enabled("true")


class TestValidateProfileLabel:
    def test_none_returns_default(self):
        assert validate_profile_label(None) == DEFAULT_PROFILE_LABEL

    def test_empty_returns_default(self):
        assert validate_profile_label("") == DEFAULT_PROFILE_LABEL

    def test_basename_is_accepted(self):
        assert validate_profile_label("dsl-batch1") == "dsl-batch1"

    def test_path_separator_rejected(self):
        with pytest.raises(ValueError, match="basename"):
            validate_profile_label("nested/label")

    def test_parent_traversal_rejected(self):
        with pytest.raises(ValueError, match="basename"):
            validate_profile_label("..")

    def test_absolute_path_rejected(self):
        with pytest.raises(ValueError, match="basename"):
            validate_profile_label("/etc/passwd")


class TestSanitizeNodeid:
    def test_simple_nodeid(self):
        nodeid = "tests/system/e2e/test_libdeobfuscated_dsl.py::TestUnflatteningRules::test_case"
        sanitized = sanitize_nodeid(nodeid)
        assert sanitized == (
            "tests__system__e2e__test_libdeobfuscated_dsl.py"
            "__TestUnflatteningRules__test_case"
        )

    def test_parametrized_nodeid_strips_unsafe_characters(self):
        nodeid = "tests/system/e2e/test_x.py::TestA::test_case[approov-flag2]"
        sanitized = sanitize_nodeid(nodeid)
        assert "[" not in sanitized
        assert "]" not in sanitized
        assert sanitized.startswith("tests__system__e2e__test_x.py__TestA__test_case")

    def test_empty_nodeid_raises(self):
        with pytest.raises(ValueError):
            sanitize_nodeid("")

    def test_result_has_no_path_separators(self):
        nodeid = "tests/system/e2e/test_x.py::Test::test_y[a/b]"
        sanitized = sanitize_nodeid(nodeid)
        assert "/" not in sanitized
        assert "\\" not in sanitized


class TestResolveProfileOutputDir:
    def test_combines_base_label_and_nodeid(self):
        nodeid = "tests/system/e2e/test_x.py::TestA::test_case"
        result = resolve_profile_output_dir(
            pathlib.Path("/work"), "dsl-batch1", nodeid
        )
        assert result == pathlib.Path(
            "/work/.tmp/profiles/dsl-batch1/"
            "tests__system__e2e__test_x.py__TestA__test_case"
        )

    def test_default_label_when_none(self):
        result = resolve_profile_output_dir(
            pathlib.Path("/work"), None, "tests/x.py::test_y"
        )
        assert result.parts[-2] == DEFAULT_PROFILE_LABEL

    def test_invalid_label_propagates(self):
        with pytest.raises(ValueError, match="basename"):
            resolve_profile_output_dir(pathlib.Path("/work"), "a/b", "tests/x.py::test_y")

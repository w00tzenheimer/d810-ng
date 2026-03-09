"""Tests for inference persistence to project JSON config."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from d810.core.rule_scope import RuleDelta
from d810.recon.persist_inference import persist_inference


def _make_config(tmp_path: Path) -> Path:
    """Create a minimal project config with one rule in each category."""
    config = {
        "ins_rules": [
            {"name": "InstructionRule", "is_activated": True, "config": {}},
        ],
        "blk_rules": [
            {"name": "ConstantFolding", "is_activated": True, "config": {}},
        ],
    }
    path = tmp_path / "test_config.json"
    path.write_text(json.dumps(config))
    return path


class TestPersistSuppressAddsToBlacklist:
    def test_suppress_adds_to_blacklist(self, tmp_path: Path) -> None:
        config_path = _make_config(tmp_path)
        deltas = [RuleDelta("ConstantFolding", "suppress", {})]
        count = persist_inference(func_ea=0x1000, deltas=deltas, config_path=config_path)

        config = json.loads(config_path.read_text())
        rule = config["blk_rules"][0]
        assert "0x1000" in rule["config"]["blacklisted_functions"]
        assert count == 1

    def test_activate_adds_to_whitelist(self, tmp_path: Path) -> None:
        config_path = _make_config(tmp_path)
        deltas = [RuleDelta("ConstantFolding", "activate", {})]
        count = persist_inference(func_ea=0x2000, deltas=deltas, config_path=config_path)

        config = json.loads(config_path.read_text())
        rule = config["blk_rules"][0]
        assert "0x2000" in rule["config"]["whitelisted_functions"]
        assert count == 1


class TestOverrideAddsPerFunctionOverrides:
    def test_override_adds_per_function_overrides(self, tmp_path: Path) -> None:
        config_path = _make_config(tmp_path)
        deltas = [RuleDelta("ConstantFolding", "override", {"max_passes": 10})]
        count = persist_inference(func_ea=0x1000, deltas=deltas, config_path=config_path)

        config = json.loads(config_path.read_text())
        rule = config["blk_rules"][0]
        assert rule["config"]["per_function_overrides"]["0x1000"]["max_passes"] == 10
        assert count == 1

    def test_override_merges_with_existing(self, tmp_path: Path) -> None:
        config_path = _make_config(tmp_path)
        deltas1 = [RuleDelta("ConstantFolding", "override", {"max_passes": 10})]
        persist_inference(func_ea=0x1000, deltas=deltas1, config_path=config_path)

        deltas2 = [RuleDelta("ConstantFolding", "override", {"max_calls": 5})]
        persist_inference(func_ea=0x1000, deltas=deltas2, config_path=config_path)

        config = json.loads(config_path.read_text())
        overrides = config["blk_rules"][0]["config"]["per_function_overrides"]["0x1000"]
        assert overrides["max_passes"] == 10
        assert overrides["max_calls"] == 5


class TestPersistIsIdempotent:
    def test_suppress_idempotent(self, tmp_path: Path) -> None:
        config_path = _make_config(tmp_path)
        deltas = [RuleDelta("ConstantFolding", "suppress", {})]
        persist_inference(func_ea=0x1000, deltas=deltas, config_path=config_path)
        persist_inference(func_ea=0x1000, deltas=deltas, config_path=config_path)

        config = json.loads(config_path.read_text())
        rule = config["blk_rules"][0]
        assert rule["config"]["blacklisted_functions"].count("0x1000") == 1

    def test_activate_idempotent(self, tmp_path: Path) -> None:
        config_path = _make_config(tmp_path)
        deltas = [RuleDelta("ConstantFolding", "activate", {})]
        persist_inference(func_ea=0x1000, deltas=deltas, config_path=config_path)
        persist_inference(func_ea=0x1000, deltas=deltas, config_path=config_path)

        config = json.loads(config_path.read_text())
        rule = config["blk_rules"][0]
        assert rule["config"]["whitelisted_functions"].count("0x1000") == 1


class TestUnknownRuleSkipped:
    def test_unknown_rule_skipped_with_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        config_path = _make_config(tmp_path)
        deltas = [RuleDelta("NonExistentRule", "suppress", {})]
        with caplog.at_level(logging.WARNING, logger="D810.recon.persist_inference"):
            count = persist_inference(func_ea=0x1000, deltas=deltas, config_path=config_path)

        assert count == 0
        assert "not found in config" in caplog.text

    def test_mixed_known_and_unknown(self, tmp_path: Path) -> None:
        config_path = _make_config(tmp_path)
        deltas = [
            RuleDelta("ConstantFolding", "suppress", {}),
            RuleDelta("Unknown", "suppress", {}),
        ]
        count = persist_inference(func_ea=0x1000, deltas=deltas, config_path=config_path)
        assert count == 1


class TestPersistInsCategoryRules:
    def test_ins_rule_suppress(self, tmp_path: Path) -> None:
        """Rules in ins_rules category are also found."""
        config_path = _make_config(tmp_path)
        deltas = [RuleDelta("InstructionRule", "suppress", {})]
        count = persist_inference(func_ea=0x3000, deltas=deltas, config_path=config_path)

        config = json.loads(config_path.read_text())
        rule = config["ins_rules"][0]
        assert "0x3000" in rule["config"]["blacklisted_functions"]
        assert count == 1

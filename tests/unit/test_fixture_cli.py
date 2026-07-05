"""Argparse-level wiring test for `d810cli.py fixture` (no IDA, no build).

Loads tools/d810cli.py directly and exercises only the parser, so it stays a
pure unit test (cmd_fixture's IDA/subprocess work is never invoked here).
"""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load_cli():
    spec = importlib.util.spec_from_file_location("d810cli", REPO / "tools/d810cli.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fixture_subverbs_are_registered():
    cli = _load_cli()
    parser = cli.build_parser()
    ns = parser.parse_args(["fixture", "retarget", "--idb", "x.i64",
                            "--func", "sub_1", "--dry-run"])
    assert ns.func is cli.cmd_fixture
    assert ns.fixture_cmd == "retarget"
    assert ns.dry_run is True


def test_fixture_add_parses_core_flags():
    cli = _load_cli()
    ns = cli.build_parser().parse_args(
        ["fixture", "add", "--idb", "x.i64", "--func", "sub_1",
         "--project", "default_unflattening_ollvm.json", "--yes"])
    assert ns.fixture_cmd == "add"
    assert ns.yes is True
    assert ns.project == "default_unflattening_ollvm.json"

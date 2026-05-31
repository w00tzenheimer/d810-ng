from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "tools" / "scripts" / "thinning_codemod_gen.py"
_spec = importlib.util.spec_from_file_location("thinning_codemod_gen", SCRIPT)
cg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cg)


def test_libcst_rewrites_whole_dotted_module():
    src = "from d810.optimizers.microcode.flow.dispatcher import x\n"
    out = cg.rewrite_imports(
        src,
        old="d810.optimizers.microcode.flow.dispatcher",
        new="d810.analyses.control_flow.dispatcher",
    )
    assert "d810.analyses.control_flow.dispatcher" in out
    assert "d810.optimizers" not in out


def test_prefix_collision_not_rewritten():
    src = "from d810.x.branch_ownership import a\n"
    out = cg.rewrite_imports(
        src, old="d810.x.branch_ownership_oracle", new="d810.y.branch_ownership_oracle"
    )
    assert out == src


def test_regex_pass_rewrites_importlib_string():
    src = 'importlib.import_module("d810.optimizers.foo")\n'
    out = cg.rewrite_text(src, old="d810.optimizers.foo", new="d810.transforms.foo")
    assert "d810.transforms.foo" in out


def test_regex_pass_is_boundary_safe():
    src = "x = d810.optimizers.foobar\n"
    out = cg.rewrite_text(src, old="d810.optimizers.foo", new="d810.transforms.foo")
    assert out == src  # foobar must not be partially renamed


def test_shim_reexports_private_names():
    shim = cg.make_alias_shim("d810.old.mod", "d810.new.mod")
    assert "sys.modules" in shim
    assert "d810.new.mod" in shim

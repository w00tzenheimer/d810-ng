from __future__ import annotations

import pytest

from tools.python_versions import (
    _run_supported_python_syntax_check,
    _select_syntax_interpreter,
)


def test_supported_syntax_check_rejects_pep701_nested_fstring_backslash(tmp_path):
    pre_pep701_versions = ((3, 10), (3, 11))
    if _select_syntax_interpreter(None, target_versions=pre_pep701_versions) is None:
        pytest.skip("pre-PEP701 Python syntax interpreter is not available")

    source = tmp_path / "bad_fstring.py"
    source.write_text(
        "node = type('N', (), {'state_label': 'STATE', 'entry_anchor': 1})()\n"
        "label = f'label=\"{_dot_escape(f\"{node.state_label}\\\\nblk[{node.entry_anchor}]\")}\"'\n",
        encoding="utf-8",
    )

    assert (
        _run_supported_python_syntax_check(
            (str(source),),
            interpreter=None,
            target_versions=pre_pep701_versions,
        )
        != 0
    )


def test_supported_syntax_check_accepts_precomputed_label(tmp_path):
    if _select_syntax_interpreter(None) is None:
        pytest.skip("supported Python syntax interpreter is not available")

    source = tmp_path / "fixed_fstring.py"
    source.write_text(
        "node = type('N', (), {'state_label': 'STATE', 'entry_anchor': 1})()\n"
        "inner = f'{node.state_label}\\nblk[{node.entry_anchor}]'\n"
        "label = f'label=\"{_dot_escape(inner)}\"'\n",
        encoding="utf-8",
    )

    assert _run_supported_python_syntax_check((str(source),), interpreter=None) == 0

from __future__ import annotations

from d810.recon.maturity import ctree_maturity_text, microcode_maturity_text


def test_microcode_maturity_text_never_returns_bare_integer() -> None:
    assert microcode_maturity_text(999) == "MMAT_999"


def test_ctree_maturity_text_uses_final_fallback() -> None:
    assert ctree_maturity_text(60) == "CMAT_FINAL"
    assert ctree_maturity_text(999) == "CMAT_999"

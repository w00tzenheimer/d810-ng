"""Source-level regressions for Cython AST behavior that Python cannot execute."""

from pathlib import Path


def test_cython_depth_signature_uses_integer_shift_for_uncached_depths() -> None:
    """Cython must not lower the signature-list multiplier to a float."""
    source = (
        Path(__file__).resolve().parents[3]
        / "src/d810/speedups/expr/c_ast.pyx"
    ).read_text(encoding="utf-8")

    assert 'return ["N"] * (1 << k)' in source

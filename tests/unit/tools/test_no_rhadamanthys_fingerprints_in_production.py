from pathlib import Path


_PRODUCTION_ROOT = Path("src/d810")

_FORBIDDEN_FINGERPRINTS = (
    "rhadamanthys",
    "sub_40a560",
    "0x40ab25",
    "0x40ab56",
    "0xa0716e5b",
    "0xa5a94b86",
    "0xabb95547",
    "0xae5a330b",
    "0xec71ca67",
    "0xf6a636ef",
    "0xfed7fac0",
)


def test_production_has_no_rhadamanthys_fingerprints() -> None:
    violations: list[str] = []
    for path in sorted(_PRODUCTION_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8").lower()
        for fingerprint in _FORBIDDEN_FINGERPRINTS:
            if fingerprint in text:
                violations.append(f"{path}: {fingerprint}")

    assert violations == []

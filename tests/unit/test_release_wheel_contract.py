"""Behavioral contract for the release wheel verification command."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest

from d810.core.plugins import BackendInfo, BackendStatus
from d810.speedups.install import NativeSpeedupsProbe, REQUIRED_NATIVE_EXTENSIONS
from tools import verify_release_wheel as release_wheel
from tools.verify_release_wheel import verify_release_wheel


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = [
    ROOT / ".github" / "workflows" / "deploy.yml",
    ROOT / ".github" / "workflows" / "wheels.yml",
]


def _backend(name: str, status: BackendStatus, reason: str | None = None) -> BackendInfo:
    return BackendInfo(name=name, status=status, origin="test", reason=reason)


def test_release_verifier_passes_when_backends_and_native_extensions_are_healthy() -> None:
    output = StringIO()

    exit_code = verify_release_wheel(
        backend_probe=lambda: [_backend("test", BackendStatus.AVAILABLE)],
        native_probe=lambda: NativeSpeedupsProbe(True, "loaded /wheel/native.so"),
        output=output,
    )

    assert exit_code == 0
    report = output.getvalue()
    assert "test" in report
    assert "loaded /wheel/native.so" in report


def test_release_verifier_fails_when_a_backend_is_broken() -> None:
    output = StringIO()

    exit_code = verify_release_wheel(
        backend_probe=lambda: [
            _backend("broken", BackendStatus.BROKEN, "import failed")
        ],
        native_probe=lambda: NativeSpeedupsProbe(True, "native extensions loaded"),
        output=output,
    )

    assert exit_code == 1
    report = output.getvalue()
    assert "broken" in report
    assert "import failed" in report


def test_release_verifier_fails_when_a_native_extension_is_unloadable() -> None:
    output = StringIO()

    exit_code = verify_release_wheel(
        backend_probe=lambda: [_backend("test", BackendStatus.AVAILABLE)],
        native_probe=lambda: NativeSpeedupsProbe(False, "c_simd: missing PyInit_c_simd"),
        output=output,
    )

    assert exit_code == 1
    assert "c_simd: missing PyInit_c_simd" in output.getvalue()


def test_release_verifier_main_uses_installed_wheel_probes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Registry:
        def probe_all(self) -> list[BackendInfo]:
            return [_backend("test", BackendStatus.AVAILABLE)]

    monkeypatch.setattr(release_wheel, "registry", lambda: Registry())
    monkeypatch.setattr(
        release_wheel,
        "inspect_native_extensions",
        lambda: NativeSpeedupsProbe(True, "native extensions loaded"),
    )

    assert release_wheel.main() == 0
    assert "native extensions loaded" in capsys.readouterr().out


def test_release_probe_covers_required_native_sentinels() -> None:
    assert REQUIRED_NATIVE_EXTENSIONS == (
        "d810.speedups.c_simd",
        "d810.speedups.expr.c_ast",
        "d810.speedups.optimizers.c_pattern_match",
    )


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_wheel_builds_invoke_release_verifier_with_required_matrix(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")

    assert 'CIBW_BUILD: "cp310-* cp311-* cp312-* cp313-*"' in text
    assert 'CIBW_ENVIRONMENT: "D810_BUILD_SPEEDUPS=1"' in text
    assert "CIBW_TEST_COMMAND:" in text
    assert "tools/verify_release_wheel.py" in text

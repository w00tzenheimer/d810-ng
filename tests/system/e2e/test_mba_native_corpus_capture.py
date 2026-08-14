"""Native producer receipt for MBA differential-report input."""

from __future__ import annotations

import contextlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import idaapi

from d810.mba.native_corpus_capture import (
    NativeMbaCorpusCapture,
    native_profile_from_outcome,
)
from d810.mba.provider_outcome import MbaProviderKind, ProviderOutcomeStatus
from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test
from d810.optimizers.microcode.instructions.pattern_matching.engine import (
    get_engine_info,
)


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE = _ROOT / "samples/src/c/mba_compiler_shapes.c"
_BINARY = _ROOT / "samples/bins/mba_compiler_shapes.dylib"
_CLI = _ROOT / "tools/scripts/mba_differential_report.py"


def _build_native_corpus_binary() -> None:
    compiler = next(
        (candidate for candidate in ("clang", "gcc", "cc") if shutil.which(candidate)),
        None,
    )
    if compiler is None:
        raise RuntimeError("native MBA corpus capture needs a C compiler")
    command = [
        compiler,
        "-shared",
        "-fPIC",
        "-O0",
        "-fno-inline",
        "-fno-builtin",
        "-fno-omit-frame-pointer",
    ]
    if Path(compiler).name.startswith("clang"):
        command.extend(("-fno-vectorize", "-fno-slp-vectorize"))
    _BINARY.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [*command, "-I", str(_ROOT / "samples/include"), "-o", str(_BINARY), str(_SOURCE)],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.usefixtures("configure_hexrays")
class TestNativeMbaCorpusCapture:
    binary_name = "mba_compiler_shapes.dylib"

    @classmethod
    def setup_class(cls) -> None:
        _build_native_corpus_binary()

    def test_real_provider_histories_produce_cli_input(
        self,
        tmp_path: Path,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        """Capture an actual accepted catalogue mutation; no synthetic rows."""

        monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
        captured_rules: list[object] = []

        @contextlib.contextmanager
        def recording_state():
            with d810_state() as state:
                yield state
                captured_rules.extend(state.current_ins_rules)

        run_deobfuscation_test(
            DeobfuscationCase(
                function="mba_shape_catalogue_01",
                description="native provider history capture",
                project="mba_compiler_shape_catalogue.json",
                must_change=True,
                required_rules=["Add_HackersDelightRule_2"],
            ),
            d810_state=recording_state,
            pseudocode_to_string=pseudocode_to_string,
        )

        applied = tuple(
            outcome
            for rule in captured_rules
            for outcome in rule.provider_outcomes()
            if outcome.provider is MbaProviderKind.CATALOGUE
            and outcome.status is ProviderOutcomeStatus.APPLIED
        )
        assert applied, "native corpus did not record an accepted catalogue outcome"
        profile = native_profile_from_outcome(applied[-1])
        capture = NativeMbaCorpusCapture(
            corpus_identity="mba-compiler-shapes-native",
            toolchain_identity={
                "ida_sdk": str(idaapi.IDA_SDK_VERSION),
                "matcher_backend": str(get_engine_info()["backend"]),
                "provider": "catalogue",
            },
        )
        case = capture.add_case(
            case_id="catalogue_01",
            stratum="catalogue",
            profile=profile,
            rules=captured_rules,
        )
        assert [outcome.provider for outcome in case.outcomes] == [
            MbaProviderKind.CATALOGUE
        ]
        assert case.outcomes[0].status is ProviderOutcomeStatus.APPLIED

        capture_path = tmp_path / "native-capture.json"
        report_path = tmp_path / "report.json"
        capture.write_json(capture_path)
        completed = subprocess.run(
            [
                sys.executable,
                str(_CLI),
                "--out",
                str(report_path),
                "--providers",
                "catalogue",
                str(capture_path),
            ],
            cwd=_ROOT,
            env={"PYTHONPATH": str(_ROOT / "src")},
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert report_path.exists()

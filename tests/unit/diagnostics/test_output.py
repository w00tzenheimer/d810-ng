from __future__ import annotations

import pytest

from d810.diagnostics.output import OutputTarget, write_output


def test_write_output_writes_utf8_file(tmp_path):
    output_path = tmp_path / "report.txt"

    write_output(OutputTarget(output_path), "state \u2603")

    assert output_path.read_text(encoding="utf-8") == "state \u2603\n"


def test_write_output_rejects_non_text(tmp_path):
    output_path = tmp_path / "report.txt"

    with pytest.raises(TypeError):
        write_output(OutputTarget(output_path), 123)  # type: ignore[arg-type]

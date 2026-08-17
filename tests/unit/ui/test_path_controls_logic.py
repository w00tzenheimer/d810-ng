from __future__ import annotations

from pathlib import Path

from d810.ui.path_controls_logic import (
    directory_chooser_initial_path,
    file_chooser_initial_path,
)


def test_directory_chooser_prefers_current_path_and_expands_home() -> None:
    assert directory_chooser_initial_path("~/logs") == str(Path("~/logs").expanduser())


def test_directory_chooser_uses_home_for_an_empty_path(monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/home/tester")))

    assert directory_chooser_initial_path("") == "/home/tester"


def test_file_chooser_prefers_the_current_file_path() -> None:
    assert file_chooser_initial_path("~/captures/post.json") == str(
        Path("~/captures/post.json").expanduser()
    )


def test_file_chooser_uses_a_suggested_filename_from_home(monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/home/tester")))

    assert file_chooser_initial_path("", suggested_filename="post-maturity.json") == (
        "/home/tester/post-maturity.json"
    )

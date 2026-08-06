from __future__ import annotations

from enum import IntFlag
from types import SimpleNamespace

import pytest

from d810.ui import qt_layout_policy


class _Alignment(IntFlag):
    LEFT = 1
    TOP = 2


class _RecordingFormLayout:
    def __init__(self) -> None:
        self.form_alignment: object | None = None
        self.label_alignment: object | None = None
        self.field_growth_policy: object | None = None

    def setFormAlignment(self, alignment: object) -> None:
        self.form_alignment = alignment

    def setLabelAlignment(self, alignment: object) -> None:
        self.label_alignment = alignment

    def setFieldGrowthPolicy(self, policy: object) -> None:
        self.field_growth_policy = policy


class _RecordingButton:
    def __init__(self) -> None:
        self.stylesheet = ""

    def setStyleSheet(self, stylesheet: str) -> None:
        self.stylesheet = stylesheet


@pytest.mark.parametrize("qt6", (False, True))
def test_form_policy_is_left_aligned_and_expands_fields(
    monkeypatch: pytest.MonkeyPatch,
    qt6: bool,
) -> None:
    growth_policy = object()
    if qt6:
        qt = SimpleNamespace(
            AlignmentFlag=SimpleNamespace(
                AlignLeft=_Alignment.LEFT,
                AlignTop=_Alignment.TOP,
            )
        )
        form_type = SimpleNamespace(
            FieldGrowthPolicy=SimpleNamespace(
                AllNonFixedFieldsGrow=growth_policy,
            )
        )
    else:
        qt = SimpleNamespace(
            AlignLeft=_Alignment.LEFT,
            AlignTop=_Alignment.TOP,
        )
        form_type = SimpleNamespace(AllNonFixedFieldsGrow=growth_policy)
    monkeypatch.setattr(qt_layout_policy, "QtCore", SimpleNamespace(Qt=qt))
    monkeypatch.setattr(
        qt_layout_policy,
        "QtWidgets",
        SimpleNamespace(QFormLayout=form_type),
    )
    layout = _RecordingFormLayout()

    qt_layout_policy.configure_left_aligned_form(layout)

    assert layout.form_alignment == _Alignment.LEFT | _Alignment.TOP
    assert layout.label_alignment == _Alignment.LEFT
    assert layout.field_growth_policy is growth_policy


def test_button_policy_is_local_left_aligned_with_leading_padding() -> None:
    button = _RecordingButton()

    qt_layout_policy.configure_left_aligned_button(button)

    assert button.stylesheet == (
        "QPushButton { text-align: left; padding-left: 8px; }"
    )

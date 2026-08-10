"""STRING_LIST fields may offer choices (jump-fixer's enabled_rules).

A list of known rule names is "pick several of these", so the field needs both
list semantics and a discoverable vocabulary. Restricting choices to ENUM forced
the alternative -- a free-text list -- which is exactly the discoverability gap
that hid every jump rule from the UI.
"""

from __future__ import annotations

import pytest

from d810.core.pass_editor_spec import FieldControlKind, FieldEditorSpec


def _field(control, choices=()):
    return FieldEditorSpec(
        field_id="f",
        label="F",
        path=("f",),
        control=control,
        description="d",
        choices=choices,
    )


def test_string_list_may_declare_choices():
    field = _field(FieldControlKind.STRING_LIST, ("A", "B"))
    assert field.choices == ("A", "B")


def test_string_list_without_choices_is_still_valid():
    """Free-text lists remain legal; choices are an optional vocabulary."""
    assert _field(FieldControlKind.STRING_LIST).choices == ()


def test_enum_still_requires_choices():
    with pytest.raises(ValueError, match="choices"):
        _field(FieldControlKind.ENUM)


@pytest.mark.parametrize(
    "control",
    [
        FieldControlKind.BOOLEAN,
        FieldControlKind.INTEGER,
        FieldControlKind.TEXT,
    ],
)
def test_scalar_controls_still_reject_choices(control):
    with pytest.raises(ValueError, match="choices"):
        _field(control, ("A",))

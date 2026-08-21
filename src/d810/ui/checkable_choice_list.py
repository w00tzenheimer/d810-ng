"""Native-safe bounded checkbox list for choice-backed editor fields."""

from __future__ import annotations

from d810.core import typing
from d810.ui.panel_density_logic import choice_list_height

try:
    from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtWidgets
except ImportError:  # Narrow fake-Qt adapters may omit the availability flag.
    from d810.qt_shim import QtWidgets

    QT_GRAPHICS_AVAILABLE = True


if QT_GRAPHICS_AVAILABLE:

    class CheckableChoiceListWidget(QtWidgets.QScrollArea):
        """Display declared choices while safely rolling back rejected edits."""

        def __init__(
            self,
            choices: tuple[str, ...],
            selected: tuple[str, ...] | list[str],
            on_selection_changed: typing.Callable[[tuple[str, ...]], bool],
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self._choices = tuple(str(choice) for choice in choices)
            if len(set(self._choices)) != len(self._choices):
                raise ValueError("choices must not contain duplicates")
            self._validate_selection(selected)
            self._selected = set(str(choice) for choice in selected)
            self._on_selection_changed = on_selection_changed
            self._checkboxes: dict[str, typing.Any] = {}

            self.setWidgetResizable(True)
            self._body = QtWidgets.QWidget()
            self._layout = QtWidgets.QVBoxLayout(self._body)
            self._layout.setContentsMargins(4, 2, 4, 2)
            self._layout.setSpacing(2)
            for choice in self._choices:
                checkbox = QtWidgets.QCheckBox(choice, self._body)
                checkbox.setChecked(choice in self._selected)
                checkbox.toggled.connect(
                    lambda checked, choice=choice, checkbox=checkbox: self._toggle(
                        choice, checkbox, bool(checked)
                    )
                )
                self._checkboxes[choice] = checkbox
                self._layout.addWidget(checkbox)
            self._layout.addStretch(1)
            self.setWidget(self._body)
            list_height = choice_list_height(len(self._choices))
            self.setMinimumHeight(list_height)
            self.setMaximumHeight(list_height)

        def choices(self) -> tuple[str, ...]:
            return self._choices

        def selected_choices(self) -> tuple[str, ...]:
            return tuple(choice for choice in self._choices if choice in self._selected)

        def checkbox_for(self, choice: str) -> QtWidgets.QCheckBox | None:
            return self._checkboxes.get(choice)

        def set_selection(self, selected: tuple[str, ...] | list[str]) -> None:
            self._validate_selection(selected)
            selected_set = set(str(choice) for choice in selected)
            self._selected = selected_set
            for choice, checkbox in self._checkboxes.items():
                checkbox.blockSignals(True)
                try:
                    checkbox.setChecked(choice in selected_set)
                finally:
                    checkbox.blockSignals(False)

        def _validate_selection(
            self,
            selected: tuple[str, ...] | list[str],
        ) -> None:
            normalized = tuple(str(choice) for choice in selected)
            if len(set(normalized)) != len(normalized):
                raise ValueError("selected choices must not contain duplicates")
            unknown = set(normalized) - set(self._choices)
            if unknown:
                raise ValueError(
                    "selected choices contain unknown values: "
                    + ", ".join(sorted(unknown))
                )

        def _toggle(
            self,
            choice: str,
            checkbox: typing.Any,
            checked: bool,
        ) -> None:
            previous = set(self._selected)
            if checked:
                self._selected.add(choice)
            else:
                self._selected.discard(choice)
            accepted = bool(self._on_selection_changed(self.selected_choices()))
            if accepted:
                return
            self._selected = previous
            checkbox.blockSignals(True)
            try:
                checkbox.setChecked(choice in previous)
            finally:
                checkbox.blockSignals(False)


else:

    class CheckableChoiceListWidget:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("CheckableChoiceListWidget requires IDA Pro Qt")


__all__ = ["CheckableChoiceListWidget"]

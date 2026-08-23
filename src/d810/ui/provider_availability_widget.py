"""Compact shared Qt rendering for optional pass implementations."""

from __future__ import annotations

from d810.core import typing
from d810.manager.workbench_recipe_models import PassImplementationAvailability

try:
    from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtWidgets
except ImportError:
    from d810.qt_shim import QtWidgets

    QT_GRAPHICS_AVAILABLE = True


if QT_GRAPHICS_AVAILABLE:

    class ProviderAvailabilityWidget(QtWidgets.QWidget):
        """Show one provider status line and hide completely when absent."""

        def __init__(self, parent: typing.Any = None) -> None:
            super().__init__(parent)
            self._label = QtWidgets.QLabel()
            self._label.setWordWrap(True)
            layout = QtWidgets.QHBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(4)
            layout.addWidget(self._label)
            layout.addStretch(1)
            self.set_availability(None)

        def set_availability(
            self,
            availability: PassImplementationAvailability | None,
        ) -> None:
            if availability is None:
                self._label.setText("")
                self._label.setToolTip("")
                self.setVisible(False)
                return
            self._label.setText(
                f"Implementation: {availability.distribution} - "
                f"{availability.status_label}"
            )
            self._label.setToolTip(availability.detail)
            self.setToolTip(availability.detail)
            self.setVisible(True)

        def display_text(self) -> str:
            """Return the exact compact text shown to the operator."""
            return self._label.text()


else:

    class ProviderAvailabilityWidget:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("ProviderAvailabilityWidget requires IDA Pro Qt")


__all__ = ["ProviderAvailabilityWidget"]

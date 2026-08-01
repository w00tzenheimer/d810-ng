"""Qt presentation for native-versus-D810 comparison evidence."""

from __future__ import annotations

from d810.core import typing
from d810.ui.workbench_logic import ComparisonArtifactView, ComparisonView

try:
    import ida_kernwin  # noqa: F401

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


if IDA_AVAILABLE:
    from d810.qt_shim import QtWidgets

    def _artifact_status(artifact: ComparisonArtifactView) -> str:
        reasons = "; ".join(artifact.reasons)
        return f"{artifact.label}: {artifact.status}" + (
            f" - {reasons}" if reasons else ""
        )

    class WorkbenchComparisonDialog(QtWidgets.QDialog):
        """Modeless, read-only comparison owned by the workbench panel."""

        def __init__(
            self,
            view: ComparisonView,
            *,
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self.setWindowTitle(
                f"D810 native comparison - function 0x{view.function_ea:X}"
            )
            self.setModal(False)
            self.resize(1100, 720)

            summary = QtWidgets.QLabel(view.summary)
            summary.setWordWrap(True)
            freshness = QtWidgets.QLabel(
                "\n".join((_artifact_status(view.native), _artifact_status(view.d810)))
            )
            freshness.setWordWrap(True)

            tabs = QtWidgets.QTabWidget()
            tabs.addTab(self._artifact_editor(view.native), "Native")
            tabs.addTab(self._artifact_editor(view.d810), "D810")

            metrics = QtWidgets.QTableWidget(len(view.metrics), 4)
            metrics.setHorizontalHeaderLabels(["Metric", "Native", "D810", "Delta"])
            try:
                no_edits = QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
            except AttributeError:
                no_edits = QtWidgets.QAbstractItemView.NoEditTriggers
            metrics.setEditTriggers(no_edits)
            for row, metric in enumerate(view.metrics):
                for column, value in enumerate(
                    (
                        metric.label,
                        metric.native_value,
                        metric.d810_value,
                        metric.delta,
                    )
                ):
                    metrics.setItem(row, column, QtWidgets.QTableWidgetItem(str(value)))
            metrics.horizontalHeader().setStretchLastSection(True)

            close_button = QtWidgets.QPushButton("Close")
            close_button.clicked.connect(self.close)
            button_row = QtWidgets.QHBoxLayout()
            button_row.addStretch(1)
            button_row.addWidget(close_button)

            layout = QtWidgets.QVBoxLayout()
            layout.addWidget(summary)
            layout.addWidget(freshness)
            layout.addWidget(tabs, 1)
            layout.addWidget(metrics)
            layout.addLayout(button_row)
            self.setLayout(layout)

        @staticmethod
        def _artifact_editor(artifact: ComparisonArtifactView) -> typing.Any:
            editor = QtWidgets.QPlainTextEdit()
            editor.setReadOnly(True)
            editor.setPlainText(artifact.text)
            editor.setPlaceholderText(
                f"{artifact.label} pseudocode is unavailable for this identity"
            )
            return editor

else:

    class WorkbenchComparisonDialog:
        """Import-safe stub used outside IDA."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("WorkbenchComparisonDialog requires IDA Pro")


__all__ = ["IDA_AVAILABLE", "WorkbenchComparisonDialog"]

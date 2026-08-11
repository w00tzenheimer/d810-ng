"""Install solver support action.

The ``mba-solve`` pass gates every rewrite on a Z3 proof, and z3 is not a
dependency of d810 or of the solver backend: it lives in ``~/.d810-speedups``,
installed by the ``install-speedups`` command, because
``ensure_speedups_on_path`` pins both the wheel and the native ``libz3`` it
loads. A second copy in IDA's site-packages would leave ``sys.path`` order
deciding which wrapper pairs with which native library.

The cost of that isolation is a reachable state where everything installs
cleanly and no proof can be produced -- so mba-solve runs and applies nothing.
This turns the remedy into one click instead of a second command line.

The work itself lives in :func:`d810.speedups.install.install_solver_support`,
which is unit-tested; this file stays a thin wrapper because the UI layer is
out of reach of the unit suite.
"""

from __future__ import annotations

from d810.core import typing
from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("d810.ui")

try:
    from d810.qt_shim import QTimer
except ImportError:
    QTimer = None  # type: ignore[assignment]


class InstallSolverSupport(D810ActionHandler):
    """Install the Z3 solver that mba-solve's proof gate needs."""

    ACTION_ID = "d810ng:install_solver_support"
    ACTION_TEXT = "Install solver support (Z3)"
    ACTION_TOOLTIP = (
        "Install Z3 into ~/.d810-speedups so mba-solve can prove its rewrites"
    )
    SUPPORTED_VIEWS = frozenset({"pseudocode", "disasm"})
    MENU_ORDER = 210
    REQUIRES_STARTED = False
    SUBMENU = "Settings"

    def execute(self, ctx: typing.Any) -> int:
        idaapi_shim = self.ida_module("idaapi")
        if idaapi_shim is None or QTimer is None:
            return 0

        def _deferred_install() -> None:
            # Runs pip, so it can take tens of seconds and WILL block the UI.
            # Deliberately not threaded: the result has to be reported through
            # IDA's API, and moving the install off-thread buys a responsive
            # window at the cost of a much easier way to crash the process.
            from d810.speedups.install import install_solver_support

            try:
                idaapi_shim.msg(
                    "d810-ng: installing solver support, IDA will be busy...\n"
                )
                result = install_solver_support()
            except Exception as exc:  # noqa: BLE001 - never escape into IDA
                logger.error("Solver support install failed: %s", exc, exc_info=True)
                idaapi_shim.warning(f"Failed to install solver support: {exc}")
                return

            if result.ok:
                # No cache to clear here: install_solver_support bumps the
                # optional-dependency generation, and backends that cache an
                # import probe re-check against it. d810 deliberately does not
                # name a solver package -- backends live out-of-tree.
                logger.info("Solver support: %s", result.message)
                idaapi_shim.info(result.message)
            else:
                logger.warning("Solver support: %s", result.message)
                idaapi_shim.warning(result.message)

        try:
            QTimer.singleShot(0, _deferred_install)
            return 1
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to schedule solver install: %s", exc, exc_info=True)
            idaapi_shim.warning(f"Failed to schedule solver install: {exc}")
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Offered only while solver support is missing.

        Once z3 resolves there is nothing to do, and an action that always
        claims work is available trains people to ignore it.
        """
        try:
            from d810.speedups.install import _default_solver_probe

            return not _default_solver_probe()
        except Exception:  # noqa: BLE001 - if we cannot tell, offer it
            return True

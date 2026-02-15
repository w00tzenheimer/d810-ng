"""D810ng context-menu builder.

``D810ContextMenu`` registers IDA action handlers and attaches them to
both the Hex-Rays pseudocode right-click menu and the disassembly view
right-click menu under a ``d810-ng/`` submenu.

Lifecycle
---------
* ``install()``  -- called once when the GUI is initialized. Registers actions
  and installs hooks to handle right-click menu population.
* ``uninstall()``  -- called once when the GUI is torn down.
* ``populating_popup()``  -- called from hooks each time a context menu is about
  to be shown.
"""
from __future__ import annotations

from d810.core import typing

from d810.core.logging import getLogger
from d810.ui.action_loader import ActionLoader

from d810.ui.actions.ida_handler import make_ida_handler

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_hexrays
    import ida_kernwin
    import idaapi
except ImportError:
    ida_hexrays = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]

if typing.TYPE_CHECKING:
    from d810.manager import D810State


class D810PopupHook(ida_hexrays.Hexrays_Hooks if ida_hexrays else object):  # type: ignore[misc]
    """Lightweight HexRays hook that populates the D-810 pseudocode context menu.

    Installed at GUI initialization time, independent of the deobfuscation hook.
    """

    def __init__(self, context_menu: "D810ContextMenu") -> None:
        if ida_hexrays is not None:
            super().__init__()
        self._context_menu = context_menu
        self._hooked = False

    def populating_popup(
        self,
        widget: typing.Any,
        popup: typing.Any,
        hx_view: typing.Any = None,
    ) -> int:
        """Attach D-810 menu items to the pseudocode right-click popup."""
        self._context_menu.populating_pseudocode_popup(widget, popup, hx_view)
        return 0

    def hook(self) -> bool:
        """Install this hook if not already installed."""
        if ida_hexrays is None or self._hooked:
            return False
        result = super().hook()  # type: ignore[misc]
        if result:
            self._hooked = True
            logger.debug("D810PopupHook (pseudocode) installed")
        return result

    def unhook(self) -> bool:
        """Remove this hook if installed."""
        if ida_hexrays is None or not self._hooked:
            return False
        result = super().unhook()  # type: ignore[misc]
        if result:
            self._hooked = False
            logger.debug("D810PopupHook (pseudocode) uninstalled")
        return result


class D810DisasmPopupHook(idaapi.UI_Hooks if idaapi else object):  # type: ignore[misc]
    """UI hook that populates the D-810 disassembly context menu.

    Installed at GUI initialization time, independent of the deobfuscation hook.
    """

    def __init__(self, context_menu: "D810ContextMenu") -> None:
        if idaapi is not None:
            super().__init__()
        self._context_menu = context_menu
        self._hooked = False

    def finish_populating_widget_popup(
        self,
        widget: typing.Any,
        popup: typing.Any,
    ) -> None:
        """Attach D-810 menu items to the disassembly right-click popup."""
        if idaapi is None:
            return
        widget_type = idaapi.get_widget_type(widget)
        if widget_type == idaapi.BWN_DISASM:
            self._context_menu.populating_disasm_popup(widget, popup)

    def hook(self) -> bool:
        """Install this hook if not already installed."""
        if idaapi is None or self._hooked:
            return False
        result = super().hook()  # type: ignore[misc]
        if result:
            self._hooked = True
            logger.debug("D810DisasmPopupHook installed")
        return result

    def unhook(self) -> bool:
        """Remove this hook if installed."""
        if idaapi is None or not self._hooked:
            return False
        result = super().unhook()  # type: ignore[misc]
        if result:
            self._hooked = False
            logger.debug("D810DisasmPopupHook uninstalled")
        return result


class D810ContextMenu:
    """Manages registration and population of d810-ng context-menu actions.

    Handles both pseudocode and disassembly view context menus.
    """

    SUBMENU_PATH = "d810-ng/"

    def __init__(self) -> None:
        self._installed = False
        self._action_instances: list[typing.Any] = []
        self._action_loader = ActionLoader()
        self._popup_hook: D810PopupHook | None = None
        self._disasm_popup_hook: D810DisasmPopupHook | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def install(self, state: "D810State") -> None:
        """Register all actions with IDA's action system and install popup hooks.

        Safe to call multiple times -- subsequent calls are no-ops.

        Uses module discovery to find and instantiate all D810ActionHandler
        subclasses under ``d810.ui.actions``.

        Args:
            state: The D810State instance to inject into action handlers.
        """
        if self._installed or ida_kernwin is None:
            return

        action_count = 0

        self._action_instances = self._action_loader.load_actions(
            state,
            ida_modules=self._collect_ida_modules(),
        )
        logger.debug(
            "Using module-based action discovery (%d actions)",
            len(self._action_instances),
        )

        for instance in self._action_instances:
            action_cls = type(instance)
            ida_handler = make_ida_handler(instance, ida_kernwin_module=ida_kernwin)
            desc = ida_kernwin.action_desc_t(
                action_cls.ACTION_ID,
                action_cls.ACTION_TEXT,
                ida_handler,
                action_cls.SHORTCUT,
                action_cls.ACTION_TOOLTIP or action_cls.ACTION_TEXT,
                -1,  # icon (default)
            )
            result = ida_kernwin.register_action(desc)
            if result:
                logger.debug("Registered action %s", action_cls.ACTION_ID)
                action_count += 1
            else:
                logger.warning("Failed to register action %s", action_cls.ACTION_ID)
        # Install the pseudocode popup hook
        self._popup_hook = D810PopupHook(self)
        self._popup_hook.hook()

        # Install the disassembly popup hook
        self._disasm_popup_hook = D810DisasmPopupHook(self)
        self._disasm_popup_hook.hook()

        self._installed = True
        logger.info("D810ContextMenu installed (%d actions)", action_count)

    def uninstall(self) -> None:
        """Unregister all actions and unhook popups.  Safe to call even if not installed."""
        if not self._installed or ida_kernwin is None:
            return

        # Unhook the popup hooks first
        if self._popup_hook is not None:
            self._popup_hook.unhook()
            self._popup_hook = None

        if self._disasm_popup_hook is not None:
            self._disasm_popup_hook.unhook()
            self._disasm_popup_hook = None

        # Unregister actions that were loaded during install
        for instance in self._action_instances:
            action_cls = type(instance)
            ida_kernwin.unregister_action(action_cls.ACTION_ID)
            logger.debug("Unregistered action %s", action_cls.ACTION_ID)

        unloaded_count = self._action_loader.unload_actions()
        logger.debug("Action loader unloaded %d actions", unloaded_count)
        self._action_instances.clear()
        self._installed = False
        logger.info("D810ContextMenu uninstalled")

    def populating_pseudocode_popup(
        self,
        widget: typing.Any,
        popup: typing.Any,
        hx_view: typing.Any = None,
    ) -> None:
        """Attach pseudocode actions to the pseudocode context-menu popup.

        Called from ``D810PopupHook.populating_popup()`` each time the user
        right-clicks in a pseudocode widget.

        Parameters
        ----------
        widget:
            The IDA widget (TWidget *) that the popup belongs to.
        popup:
            The popup handle (TPopupMenu *) to attach items to.
        hx_view:
            The ``vdui_t`` for the pseudocode view, or ``None``.
        """
        if not self._installed or ida_kernwin is None:
            return

        # Filter and sort by MENU_ORDER
        pseudocode_actions = [
            action for action in self._action_instances if "pseudocode" in action.SUPPORTED_VIEWS
        ]
        pseudocode_actions.sort(key=lambda action: action.MENU_ORDER)

        for action in pseudocode_actions:
            # Determine submenu path
            submenu_path = self.SUBMENU_PATH
            if action.SUBMENU:
                submenu_path = f"{self.SUBMENU_PATH}{action.SUBMENU}/"

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                action.ACTION_ID,
                submenu_path,
            )

    def populating_disasm_popup(
        self,
        widget: typing.Any,
        popup: typing.Any,
    ) -> None:
        """Attach disassembly actions to the disassembly context-menu popup.

        Called from ``D810DisasmPopupHook.finish_populating_widget_popup()`` each time
        the user right-clicks in a disassembly widget.

        Parameters
        ----------
        widget:
            The IDA widget (TWidget *) that the popup belongs to.
        popup:
            The popup handle (TPopupMenu *) to attach items to.
        """
        if not self._installed or ida_kernwin is None:
            return

        # Filter and sort by MENU_ORDER
        disasm_actions = [
            action for action in self._action_instances if "disasm" in action.SUPPORTED_VIEWS
        ]
        disasm_actions.sort(key=lambda action: action.MENU_ORDER)

        for action in disasm_actions:
            # Determine submenu path
            submenu_path = self.SUBMENU_PATH
            if action.SUBMENU:
                submenu_path = f"{self.SUBMENU_PATH}{action.SUBMENU}/"

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                action.ACTION_ID,
                submenu_path,
            )

    @property
    def is_installed(self) -> bool:
        return self._installed

    @staticmethod
    def _collect_ida_modules() -> dict[str, typing.Any]:
        modules: dict[str, typing.Any] = {}
        for module_name in (
            "idaapi",
            "ida_kernwin",
            "ida_hexrays",
            "ida_loader",
            "ida_funcs",
            "ida_fpro",
            "ida_lines",
            "ida_name",
            "ida_bytes",
            "idc",
        ):
            try:
                modules[module_name] = __import__(module_name)
            except ImportError:
                continue
        return modules

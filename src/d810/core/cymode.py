import dataclasses
import os

from .registry import survives_reload
from .singleton import SingletonMeta


def _get_default_cython_enabled() -> bool:
    """Check D810_NO_CYTHON env var to determine default state."""
    env_val = os.environ.get("D810_NO_CYTHON", "").lower()
    if env_val in ("1", "true", "yes"):
        return False
    return True


@survives_reload()
@dataclasses.dataclass(slots=True)
class CythonMode(metaclass=SingletonMeta):
    """
    Provides a controller to enable or disable the Cython-accelerated
    implementations of performance-critical code at runtime.

    Set D810_NO_CYTHON=1 environment variable to disable Cython at startup.

    Three Integration Patterns
    ---------------------------

    Pattern 1: Gate Module (Recommended)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Use a dispatcher module that attempts Cython import with CythonMode check,
    falls back to pure Python on failure.

    File structure:
        - `module.py` - gate module (imports from c_module or p_module)
        - `c_module.pyx` - Cython implementation
        - `p_module.py` - pure Python implementation

    Example (module.py):
        from d810.core.cymode import CythonMode

        if CythonMode().is_enabled():
            try:
                from d810.speedups.c_module import fast_function
                _USING_CYTHON = True
            except ImportError:
                from d810.module.p_module import fast_function
                _USING_CYTHON = False
        else:
            from d810.module.p_module import fast_function
            _USING_CYTHON = False

    Pattern 2: CythonImporter Helper
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Use the CythonImporter helper for consistent import behavior.

    Example:
        from d810.core.cymode import CythonImporter

        importer = CythonImporter()
        try:
            hash_mop = importer.import_attr("d810.speedups.cythxr._chexrays_api", "hash_mop")
        except ImportError:
            hash_mop = None

    Pattern 3: Runtime Dispatch
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    For modules with mixed Cython/Python functions, use runtime checks.

    Example:
        from d810.core.cymode import CythonMode

        def process_data(data):
            if CythonMode().is_enabled():
                try:
                    from d810.speedups import fast_process
                    return fast_process(data)
                except ImportError:
                    pass
            return slow_process(data)
    """

    _enabled: bool = dataclasses.field(default_factory=_get_default_cython_enabled)

    def _set_flag(self, value: bool) -> None:
        self._enabled = bool(value)

    def enable(self) -> None:
        """Point the public API to the fast Cython implementations."""
        if not self._enabled:
            self._set_flag(True)
            print("Cython speedups ENABLED.")

    def disable(self) -> None:
        """Point the public API to the pure Python implementations for debugging."""
        if self._enabled:
            self._set_flag(False)
            print("Cython speedups DISABLED (using pure Python).")

    def is_enabled(self) -> bool:
        """Check if the Cython implementation is currently active."""
        return self._enabled

    def toggle(self) -> None:
        """Toggle the Cython implementation on/off."""
        if self._enabled:
            self.disable()
        else:
            self.enable()


class CythonImporter:
    """Helper for importing Cython modules with CythonMode awareness.

    Raises ImportError if CythonMode is disabled, allowing normal fallback logic.

    Example:
        importer = CythonImporter()
        try:
            fast_func = importer.import_attr("d810.speedups.module", "fast_func")
        except ImportError:
            fast_func = slow_func
    """

    def __init__(self):
        self._mode = CythonMode()

    def import_module(self, module_name: str):
        """Import a Cython module if CythonMode is enabled.

        Args:
            module_name: Fully qualified module name

        Returns:
            The imported module

        Raises:
            ImportError: If CythonMode is disabled or module doesn't exist
        """
        if not self._mode.is_enabled():
            raise ImportError(f"CythonMode disabled, skipping {module_name}")

        import importlib
        return importlib.import_module(module_name)

    def import_attr(self, module_name: str, attr_name: str):
        """Import a specific attribute from a Cython module.

        Args:
            module_name: Fully qualified module name
            attr_name: Attribute name to import

        Returns:
            The imported attribute

        Raises:
            ImportError: If CythonMode is disabled or attribute doesn't exist
        """
        module = self.import_module(module_name)
        return getattr(module, attr_name)

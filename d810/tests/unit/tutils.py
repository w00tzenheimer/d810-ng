import importlib
import sys
import types
from contextlib import contextmanager
from pathlib import Path


class MockIdaDiskio:
    @staticmethod
    def get_user_idadir():
        return Path("mock_idadir")


@contextmanager
def load_conf_classes():
    # Backup any existing ida_diskio module
    orig = sys.modules.get("ida_diskio")
    # Inject dummy ida_diskio module before importing d810.conf
    dummy_mod = types.ModuleType("ida_diskio")
    setattr(dummy_mod, "get_user_idadir", MockIdaDiskio.get_user_idadir)
    sys.modules["ida_diskio"] = dummy_mod
    try:
        module = importlib.import_module("d810.conf")
        yield module.D810Configuration, module.ProjectConfiguration, module.RuleConfiguration
    finally:
        # Restore original module or remove dummy
        if orig is not None:
            sys.modules["ida_diskio"] = orig
        else:
            sys.modules.pop("ida_diskio", None)

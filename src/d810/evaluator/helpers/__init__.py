"""Helper discovery for microcode evaluation helpers.

Importing this package triggers side-effect imports of all helper
modules so that :class:`~d810.core.registry.Registrant.__init_subclass__`
fires and populates ``_RotateHelper.registry`` for every concrete helper.
"""

from __future__ import annotations

from d810._vendor.ida_reloader.ida_reloader import Scanner
import d810.evaluator.helpers.rotate as _rotate_mod  # noqa: F401 (side-effect import)
from d810.evaluator.helpers.rotate import _RotateHelper

# Discover any additional helper modules added to this package in the future
Scanner.scan(__path__, prefix=__name__ + ".", skip_packages=True)

__all__ = ["_RotateHelper"]

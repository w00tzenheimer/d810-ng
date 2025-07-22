# typing backports
from __future__ import annotations

import sys

# Multiple python version compatible import for typing.override
if sys.version_info >= (3, 12):
    from typing import override  # noqa: F401
else:
    from typing_extensions import override  # noqa: F401

# Multiple python version compatible import for Self, StrEnum,
if sys.version_info >= (3, 11):
    from typing import Self  # noqa: F401
else:
    from typing_extensions import Self  # noqa: F401

# Multiple python version compatible import for typing.NotRequired
if sys.version_info >= (3, 11):
    from typing import NotRequired  # noqa: F401
else:
    from typing_extensions import NotRequired  # noqa: F401


# Multiple python version compatible import for typing.LiteralString
if sys.version_info >= (3, 11):
    from typing import LiteralString  # noqa: F401
else:
    from typing_extensions import LiteralString  # noqa: F401


# Multiple python version compatible import for typing.TypeAliasType
if sys.version_info >= (3, 12):
    from typing import TypeAliasType  # noqa: F401
else:
    from typing_extensions import TypeAliasType  # noqa: F401

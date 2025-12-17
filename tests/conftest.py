"""Pytest configuration for d810-ng tests.

Shared configuration for all test suites.
Note: Clang-related fixtures are in tests/system/conftest.py for system tests.
"""

import logging
import os
import pathlib
import sys
from dataclasses import dataclass

import pytest

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add project root to path for all tests to ensure imports work
PROJECT_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))


# region .env Loader
def _maybe_load_dotenv(path: pathlib.Path) -> None:
    """
    Load a simple .env file into os.environ without external deps.
    Does not override existing environment variables.
    """
    if not path.is_file():
        return

    logger.info("Loading environment from %s", path)

    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        logger.warning("Failed to read .env at %s", path)
        return

    for line in content.splitlines():
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#") or "=" not in line:
            continue

        # Handle 'export ' prefix
        if line.startswith("export "):
            line = line[7:]

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        # Remove surrounding quotes
        if len(value) >= 2 and value[0] in ('"', "'") and value[0] == value[-1]:
            value = value[1:-1]

        # Only set if not already present in environment
        if key and key not in os.environ:
            os.environ[key] = value


# endregion


# region Helpers
@dataclass(frozen=True)
class EnvWrapper:
    """Helper object to access environment variables with type conversion."""

    def as_str(self, key: str, default: str = "") -> str:
        return os.environ.get(key, default)

    def as_int(self, key: str, default: int = 0) -> int:
        val = os.environ.get(key)
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def as_bool(self, key: str, default: bool = False) -> bool:
        val = os.environ.get(key)
        if val is None:
            return default
        return val.lower() in ("1", "true", "yes", "on")

    def as_list(self, key: str, separator: str = ",") -> list[str]:
        val = os.environ.get(key)
        if not val:
            return []
        # Handle both comma and semicolon, just in case
        cleaned = val.replace(";", separator)
        return [item.strip() for item in cleaned.split(separator) if item.strip()]

    def as_path(self, key: str, default: pathlib.Path | str = "") -> pathlib.Path:
        """
        Returns the environment variable as a Path, or default if not set.
        The default can be either a str or Path.
        """
        val = os.environ.get(key)
        if val:
            return pathlib.Path(val)
        return pathlib.Path(default)


# endregion


@pytest.fixture(scope="session")
def env() -> EnvWrapper:
    """
    Session fixture that loads .env and returns a helper object.

    Usage in tests:
        def test_something(env):
            if env.as_bool("DEBUG"):
                assert env.as_int("MAX_RETRIES") == 5
    """
    # 1. Try current working directory
    env_path = pathlib.Path.cwd() / ".env"

    # 2. Fallback to project root
    if not env_path.exists():
        env_path = PROJECT_ROOT / ".env"

    _maybe_load_dotenv(env_path)

    return EnvWrapper()


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "ida_required: mark test as requiring IDA Pro")
    config.addinivalue_line("markers", "integration: mark test as integration test")

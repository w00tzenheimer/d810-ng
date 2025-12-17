"""Platform and file format detection utilities.

This module provides utilities for detecting the binary file format
and platform characteristics, useful for architecture-specific rule configuration.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import TYPE_CHECKING

from .logging import getLogger

logger = getLogger(__name__)


class FileFormat(Enum):
    """Binary file format types."""

    UNKNOWN = auto()
    MACHO = auto()  # Mach-O (macOS, iOS)
    ELF = auto()  # ELF (Linux, BSD)
    PE = auto()  # PE/COFF (Windows)
    RAW = auto()  # Raw binary


class Platform(Enum):
    """Target platform/OS."""

    UNKNOWN = auto()
    DARWIN = auto()  # macOS, iOS
    LINUX = auto()
    WINDOWS = auto()


# IDA file type constants (from ida_loader.h)
# These match the f_XXX constants in IDA SDK
_IDA_FILETYPE_ELF = 18  # f_ELF
_IDA_FILETYPE_MACHO = 25  # f_MACHO
_IDA_FILETYPE_PE = 11  # f_PE
_IDA_FILETYPE_COFF = 20  # f_COFF


def detect_file_format() -> FileFormat:
    """Detect the file format of the currently loaded binary.

    Returns:
        FileFormat enum value based on the current IDB.

    Note:
        Must be called from within IDA with a database loaded.
    """
    try:
        import idaapi
        # Use idaapi shim - works across IDA versions
        filetype = idaapi.inf_get_filetype()

        if filetype == _IDA_FILETYPE_MACHO:
            return FileFormat.MACHO
        elif filetype == _IDA_FILETYPE_ELF:
            return FileFormat.ELF
        elif filetype in (_IDA_FILETYPE_PE, _IDA_FILETYPE_COFF):
            return FileFormat.PE
        else:
            logger.debug("Unknown file type: %d", filetype)
            return FileFormat.UNKNOWN
    except Exception as e:
        logger.warning("Failed to detect file format: %s", e)
        return FileFormat.UNKNOWN


def detect_platform() -> Platform:
    """Detect the target platform based on the file format.

    This is a heuristic based on file format - Mach-O implies Darwin,
    PE implies Windows, ELF implies Linux (though ELF is used on BSD too).

    Returns:
        Platform enum value.
    """
    file_format = detect_file_format()

    if file_format == FileFormat.MACHO:
        return Platform.DARWIN
    elif file_format == FileFormat.PE:
        return Platform.WINDOWS
    elif file_format == FileFormat.ELF:
        return Platform.LINUX
    else:
        return Platform.UNKNOWN


def get_format_config_keys(file_format: FileFormat | None = None) -> list[str]:
    """Get configuration keys to check for the given file format.

    Returns a list of keys in order of precedence (most specific first).
    This allows configs to specify overrides by format name.

    Args:
        file_format: The file format, or None to detect automatically.

    Returns:
        List of config keys to check, e.g., ["macho", "darwin", "default"]
    """
    if file_format is None:
        file_format = detect_file_format()

    keys = []

    # File format specific key (most specific)
    if file_format == FileFormat.MACHO:
        keys.extend(["macho", "darwin"])
    elif file_format == FileFormat.ELF:
        keys.extend(["elf", "linux"])
    elif file_format == FileFormat.PE:
        keys.extend(["pe", "windows"])

    # Default fallback (least specific)
    keys.append("default")

    return keys


# Reserved keys that indicate arch-specific config structure
ARCH_CONFIG_KEYS = frozenset(
    {"default", "macho", "elf", "pe", "darwin", "linux", "windows"}
)


def is_arch_specific_config(config: dict) -> bool:
    """Check if a config dict uses architecture-specific structure.

    Args:
        config: The rule configuration dict.

    Returns:
        True if the config contains architecture-specific keys.
    """
    return bool(ARCH_CONFIG_KEYS & set(config.keys()))


def resolve_arch_config(config: dict, file_format: FileFormat | None = None) -> dict:
    """Resolve architecture-specific configuration to effective config.

    If the config contains architecture-specific keys (default, macho, elf, pe,
    darwin, linux, windows), this merges the default config with the most
    specific matching config for the current binary.

    If the config doesn't use arch-specific structure, returns it unchanged
    for backwards compatibility.

    Args:
        config: The rule configuration dict (may or may not be arch-specific).
        file_format: The file format, or None to detect automatically.

    Returns:
        The effective configuration dict.

    Example:
        >>> config = {
        ...     "default": {"min_size": 4},
        ...     "macho": {"allow_executable_readonly": True}
        ... }
        >>> # On a Mach-O binary:
        >>> resolve_arch_config(config)
        {"min_size": 4, "allow_executable_readonly": True}
    """
    if not is_arch_specific_config(config):
        # No arch-specific structure - return as-is for backwards compatibility
        return config

    # Start with default config
    result = dict(config.get("default", {}))

    # Get keys to check for this platform (most specific to least)
    keys_to_check = get_format_config_keys(file_format)

    # Apply overrides from most specific matching key
    for key in keys_to_check:
        if key in config and key != "default":
            override = config[key]
            if isinstance(override, dict):
                result.update(override)
                logger.debug(
                    "Applied arch-specific config for '%s': %s", key, override
                )
            break  # Only apply the most specific override

    return result

"""Pure logic for export microcode action.

This module contains the business logic for exporting microcode at various
maturity levels, separated from IDA dependencies to enable unit testing.

All functions in this module can be imported and tested without IDA Pro.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MicrocodeExportSettings:
    """Settings for microcode export.

    Attributes:
        maturity: Maturity level name (MMAT_GENERATED, MMAT_PREOPTIMIZED, etc.)
        pre_deobfuscation: If True, export pre-deobfuscation snapshot (hooks suppressed)
        output_path: Path to output JSON file
    """
    maturity: str = "MMAT_LVARS"
    pre_deobfuscation: bool = True
    output_path: str = ""


# All 8 microcode maturity levels: (name, description)
# These correspond to ida_hexrays.mba_maturity_t enum values 0-7
MATURITY_CHOICES: list[tuple[str, str]] = [
    ("MMAT_GENERATED", "0 - Generated (initial microcode)"),
    ("MMAT_PREOPTIMIZED", "1 - Pre-optimized (after pattern matching)"),
    ("MMAT_LOCOPT", "2 - Local optimization (peephole, constant folding)"),
    ("MMAT_CALLS", "3 - Calls (after call analysis)"),
    ("MMAT_GLBOPT1", "4 - Global optimization 1 (inter-block)"),
    ("MMAT_GLBOPT2", "5 - Global optimization 2 (final inter-block)"),
    ("MMAT_GLBOPT3", "6 - Global optimization 3 (post SSA)"),
    ("MMAT_LVARS", "7 - Local variables (final, ready for ctree)"),
]


def validate_export_settings(settings: MicrocodeExportSettings) -> tuple[bool, str]:
    """Validate microcode export settings.

    Args:
        settings: Export settings to validate

    Returns:
        Tuple of (is_valid, error_message). error_message is empty string if valid.

    Examples:
        >>> s = MicrocodeExportSettings(maturity="MMAT_LVARS", output_path="/tmp/out.json")
        >>> validate_export_settings(s)
        (True, '')
        >>> s = MicrocodeExportSettings(maturity="INVALID", output_path="/tmp/out.json")
        >>> valid, msg = validate_export_settings(s)
        >>> valid
        False
        >>> "Unknown maturity" in msg
        True
        >>> s = MicrocodeExportSettings(maturity="MMAT_LVARS", output_path="")
        >>> valid, msg = validate_export_settings(s)
        >>> valid
        False
        >>> "output_path" in msg
        True
    """
    # Check maturity is valid
    valid_maturities = [name for name, _ in MATURITY_CHOICES]
    if settings.maturity not in valid_maturities:
        return False, f"Unknown maturity level: {settings.maturity}. Valid options: {valid_maturities}"

    # Check output path is set
    if not settings.output_path:
        return False, "output_path must be set"

    return True, ""


def maturity_name_to_int(name: str) -> int | None:
    """Map maturity name to integer value.

    Maps MMAT_* names to their integer values (0-7) matching ida_hexrays.mba_maturity_t.

    Args:
        name: Maturity level name (e.g., "MMAT_GENERATED")

    Returns:
        Integer value (0-7), or None if name is invalid

    Examples:
        >>> maturity_name_to_int("MMAT_GENERATED")
        0
        >>> maturity_name_to_int("MMAT_PREOPTIMIZED")
        1
        >>> maturity_name_to_int("MMAT_LOCOPT")
        2
        >>> maturity_name_to_int("MMAT_LVARS")
        7
        >>> maturity_name_to_int("INVALID")
        >>> maturity_name_to_int("INVALID") is None
        True
    """
    maturity_map = {
        "MMAT_GENERATED": 0,
        "MMAT_PREOPTIMIZED": 1,
        "MMAT_LOCOPT": 2,
        "MMAT_CALLS": 3,
        "MMAT_GLBOPT1": 4,
        "MMAT_GLBOPT2": 5,
        "MMAT_GLBOPT3": 6,
        "MMAT_LVARS": 7,
    }

    return maturity_map.get(name)


def suggest_microcode_filename(func_name: str, maturity: str, pre: bool) -> str:
    """Generate suggested filename for microcode export.

    Sanitizes function name and adds maturity level and pre/post suffix.

    Args:
        func_name: Function name to sanitize
        maturity: Maturity level name (e.g., "MMAT_LVARS")
        pre: If True, append "_pre" suffix, else "_post"

    Returns:
        Sanitized filename with .json extension

    Examples:
        >>> suggest_microcode_filename("my_function", "MMAT_LVARS", True)
        'my_function_LVARS_pre.json'
        >>> suggest_microcode_filename("my_function", "MMAT_LOCOPT", False)
        'my_function_LOCOPT_post.json'
        >>> suggest_microcode_filename("operator<<", "MMAT_GENERATED", True)
        'operator___GENERATED_pre.json'
        >>> suggest_microcode_filename("my::func<int>", "MMAT_CALLS", False)
        'my__func_int__CALLS_post.json'
    """
    # Sanitize function name (remove invalid filename characters)
    import re
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", func_name)
    sanitized = sanitized.replace(" ", "_")

    # Limit length for base name
    if len(sanitized) > 80:
        sanitized = sanitized[:80]

    # Extract short maturity name (remove MMAT_ prefix)
    short_maturity = maturity.replace("MMAT_", "")

    # Add suffix
    suffix = "pre" if pre else "post"

    return f"{sanitized}_{short_maturity}_{suffix}.json"

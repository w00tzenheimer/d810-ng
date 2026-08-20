from collections.abc import Collection, Mapping
from dataclasses import dataclass
from d810.core.typing import Any

import ida_hexrays

from d810.hexrays.utils.hexrays_formatters import string_to_maturity


@dataclass(frozen=True)
class ConfigParam:
    """Typed metadata for a single configuration parameter.

    Used by the UI to auto-generate proper editors for rule configuration.
    """

    name: str
    type: type  # bool, int, str, list, float, dict
    default: Any
    description: str
    choices: tuple | None = None  # for enum-like params


# Practical maturities - MMAT_GLBOPT3 is rarely/never called by Hex-Rays
# MMAT_GLBOPT2 is the latest practical maturity level for most operations
DEFAULT_INSTRUCTION_MATURITIES = [
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
    ida_hexrays.MMAT_GLBOPT2,
    ida_hexrays.MMAT_LVARS,
]
DEFAULT_FLOW_MATURITIES = [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]


class MaturityContractError(ValueError):
    """A live rule disagrees with its portable maturity contract."""


class OptimizationRule:
    NAME = None
    DESCRIPTION = None
    CATEGORY: str = "General"
    CONFIG_SCHEMA: tuple[ConfigParam, ...] = (
        ConfigParam(
            "maturities",
            list,
            [],
            "Microcode maturity levels to run at",
            choices=(
                "MMAT_GENERATED",
                "MMAT_PREOPTIMIZED",
                "MMAT_LOCOPT",
                "MMAT_CALLS",
                "MMAT_GLBOPT1",
                "MMAT_GLBOPT2",
                "MMAT_GLBOPT3",
                "MMAT_LVARS",
            ),
        ),
        ConfigParam(
            "dump_intermediate_microcode", bool, False, "Dump microcode for debugging"
        ),
    )

    def __init__(self):
        self.maturities = []
        self._default_maturities: tuple[int, ...] | None = None
        self.config = {}
        self.log_dir = None
        self.dump_intermediate_microcode = False

    def set_log_dir(self, log_dir):
        self.log_dir = log_dir

    def configure(self, kwargs):
        if self._default_maturities is None:
            # Rule instances are reused across project switches. Capture the
            # concrete subclass defaults on first configuration, after every
            # subclass constructor has had a chance to set ``maturities``.
            self._default_maturities = tuple(self.maturities)
        self.config = kwargs if kwargs is not None else {}
        if "maturities" in self.config:
            self.maturities = [string_to_maturity(x) for x in self.config["maturities"]]
        else:
            self.maturities = list(self._default_maturities)
        if "dump_intermediate_microcode" in self.config:
            self.dump_intermediate_microcode = self.config[
                "dump_intermediate_microcode"
            ]

    @property
    def default_maturities(self) -> tuple[int, ...]:
        """Return the implementation's declared defaults, before overrides."""

        if self._default_maturities is not None:
            return self._default_maturities
        return tuple(self.maturities)

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__

    @property
    def description(self):
        if self.DESCRIPTION is not None:
            return self.DESCRIPTION
        return "No description available"


def _format_maturity_values(values: Collection[object]) -> str:
    return "[" + ", ".join(repr(value) for value in sorted(values, key=repr)) + "]"


def validate_rule_maturity_contract(
    rule: object,
    *,
    pass_id: str,
    stage_id: str,
    expected_supported: Collection[int],
    expected_effective: Collection[int],
) -> None:
    """Assert that a configured live rule matches a compiled stage contract.

    The expected values are supplied by the portable compiler.  This helper
    never derives them from the live rule; it only compares the live default
    and configured values against that authority.
    """

    implementation_name = str(
        getattr(rule, "name", rule.__class__.__name__)
    )
    expected_supported_set = set(expected_supported)
    expected_effective_set = set(expected_effective)
    default_values = getattr(rule, "default_maturities", None)
    if default_values is None:
        default_values = getattr(rule, "_default_maturities", None)
    if default_values is None:
        default_values = getattr(rule, "maturities", ())
    default_set = set(default_values)
    if default_set != expected_supported_set:
        raise MaturityContractError(
            f"{pass_id} stage {stage_id} implementation {implementation_name} "
            "default maturity support drift: expected "
            f"{_format_maturity_values(expected_supported_set)}, got "
            f"{_format_maturity_values(default_set)}"
        )

    configured_set = set(getattr(rule, "maturities", ()))
    if configured_set != expected_effective_set:
        raise MaturityContractError(
            f"{pass_id} stage {stage_id} implementation {implementation_name} "
            "reported an effective maturity set different from the compiled "
            f"schedule: expected {_format_maturity_values(expected_effective_set)}, "
            f"got {_format_maturity_values(configured_set)}"
        )


def configure_rule_with_maturity_contract(
    rule: object,
    config: Mapping[str, object],
    *,
    pass_id: str,
    stage_id: str,
    expected_supported: Collection[int],
    expected_effective: Collection[int],
) -> None:
    """Configure one live rule and fail closed if it rejects its schedule."""

    implementation_name = str(
        getattr(rule, "name", rule.__class__.__name__)
    )
    try:
        rule.configure(config)
    except Exception as exc:  # noqa: BLE001 - contract boundary must be precise
        raise MaturityContractError(
            f"{pass_id} stage {stage_id} implementation {implementation_name} "
            "cannot accept the compiled maturity set "
            f"{_format_maturity_values(expected_effective)}: {exc}"
        ) from exc
    validate_rule_maturity_contract(
        rule,
        pass_id=pass_id,
        stage_id=stage_id,
        expected_supported=expected_supported,
        expected_effective=expected_effective,
    )

"""
d810.core: IDA-independent core utilities and infrastructure.

This package contains foundational modules that do not depend on IDA Pro
and can be unit tested in isolation.

Modules:
    cache       - LRU/LFU caching with expiration and eviction policies
    config      - D810Configuration and ProjectConfiguration
    cymode      - CythonMode toggle for switching implementations
    logging     - D810Logger with MDC support, configure_loggers
    persistence - SQLite-backed persistent storage for optimization results
    project     - ProjectManager for configuration discovery
    registry    - Registrant metaclass, EventEmitter, utility decorators
    singleton   - Thread-safe SingletonMeta metaclass
    stats       - OptimizationStatistics tracking
    typing      - Cross-version typing compatibility imports
"""

# Configuration
from .config import (
    D810Configuration,
    ProjectConfiguration,
    RuleConfiguration,
    ConfigConstants,
    DEFAULT_IDA_USER_DIR,
)

# Logging
from .logging import (
    D810Logger,
    getLogger,
    configure_loggers,
    clear_logs,
    LoggerConfigurator,
    LevelFlag,
)

# Caching
from .cache import (
    Cache,
    CacheImpl,
    Stats,
    LRU,
    LRI,
    LFU,
    OverweightError,
    cache,
    lru_cache,
)

# Registry and patterns
from .registry import (
    Registrant,
    Registry,
    EventEmitter,
    survives_reload,
    reify,
    deferred_property,
    FilterableGenerator,
    NOT_GIVEN,
    NotGiven,
    typecheck,
    typename,
    resolve_forward_ref,
    lazy_type,
    get_all_subclasses,
)

from .singleton import SingletonMeta, singleton

# Project management
from .project import ProjectManager, ProjectContext

# Persistence (SQLite storage)
from .persistence import (
    OptimizationStorage,
    FunctionFingerprint,
    CachedResult,
    FunctionRuleConfig,
)

# Statistics
from .stats import OptimizationStatistics, OptimizationEvent, RuleExecution

# Cython mode
from .cymode import CythonMode

# Bitwise operation constants and utilities
from .bits import (
    SUB_TABLE,
    AND_TABLE,
    MSB_TABLE,
    CTYPE_SIGNED_TABLE,
    CTYPE_UNSIGNED_TABLE,
    unsigned_to_signed,
    signed_to_unsigned,
    get_msb,
    get_add_cf,
    get_add_of,
    get_sub_cf,
    get_sub_of,
    get_parity_flag,
    ror,
    rol,
    __rol__,
    __ror__,
    __ROL1__,
    __ROL2__,
    __ROL4__,
    __ROL8__,
    __ROR1__,
    __ROR2__,
    __ROR4__,
    __ROR8__,
)

# Re-export typing module contents for convenience
from . import typing

# Merkle tree utilities
from .merkle import MerkleTree

# Binary patching helpers
from .patching import PatchAction, PatchRecorder, BinaryPatcher

# Ctree snapshot helpers
from .ctree_snapshot import (
    serialize_ctree,
    deserialize_ctree,
    save_ctree_snapshot,
    load_ctree_snapshot,
)

# Platform and file format detection
from .platform import (
    FileFormat,
    Platform,
    detect_file_format,
    detect_platform,
    get_format_config_keys,
    is_arch_specific_config,
    resolve_arch_config,
    ARCH_CONFIG_KEYS,
)


# =============================================================================
# MOP (Microcode OPerand) Caches
# =============================================================================
# These caches are defined here to avoid circular imports. They were previously
# in d810.optimizers.caching, but that module has IDA-specific imports that
# create circular dependencies when d810.expr.p_ast tries to import them.


@survives_reload(reload_key="_SHARED_MOP_CACHES")
class _SharedMopCaches:
    """
    Holds the global mop caches and survives module reloads so every
    importer (Python or Cython) sees the same instances.
    """

    def __init__(self) -> None:
        # Keep sizes reasonable; tweak as needed elsewhere.
        self.MOP_CONSTANT_CACHE = CacheImpl(max_size=1000)
        self.MOP_TO_AST_CACHE = CacheImpl(max_size=20480)


_shared_caches = _SharedMopCaches()

# Public module-level aliases used throughout the codebase (and Cython)
MOP_CONSTANT_CACHE = _shared_caches.MOP_CONSTANT_CACHE
"""Cache for constant microcode operand lookups."""

MOP_TO_AST_CACHE = _shared_caches.MOP_TO_AST_CACHE
"""Cache for microcode operand to AST conversions."""


__all__ = [
    # config
    "D810Configuration",
    "ProjectConfiguration",
    "RuleConfiguration",
    "ConfigConstants",
    "DEFAULT_IDA_USER_DIR",
    # logging
    "D810Logger",
    "getLogger",
    "configure_loggers",
    "clear_logs",
    "LoggerConfigurator",
    "LevelFlag",
    # cache
    "Cache",
    "CacheImpl",
    "Stats",
    "LRU",
    "LRI",
    "LFU",
    "OverweightError",
    "cache",
    "lru_cache",
    # registry
    "Registrant",
    "Registry",
    "EventEmitter",
    "survives_reload",
    "reify",
    "deferred_property",
    "FilterableGenerator",
    "NOT_GIVEN",
    "NotGiven",
    "typecheck",
    "typename",
    "resolve_forward_ref",
    "lazy_type",
    "get_all_subclasses",
    # singleton
    "SingletonMeta",
    "singleton",
    # project
    "ProjectManager",
    "ProjectContext",
    # persistence
    "OptimizationStorage",
    "FunctionFingerprint",
    "CachedResult",
    "FunctionRuleConfig",
    # stats
    "OptimizationStatistics",
    "OptimizationEvent",
    "RuleExecution",
    # cymode
    "CythonMode",
    # constants
    "SUB_TABLE",
    "AND_TABLE",
    "MSB_TABLE",
    "CTYPE_SIGNED_TABLE",
    "CTYPE_UNSIGNED_TABLE",
    # bits (bitwise utilities)
    "unsigned_to_signed",
    "signed_to_unsigned",
    "get_msb",
    "get_add_cf",
    "get_add_of",
    "get_sub_cf",
    "get_sub_of",
    "get_parity_flag",
    "ror",
    "rol",
    "__rol__",
    "__ror__",
    "__ROL1__",
    "__ROL2__",
    "__ROL4__",
    "__ROL8__",
    "__ROR1__",
    "__ROR2__",
    "__ROR4__",
    "__ROR8__",
    # typing module
    "typing",
    # MOP caches
    "MOP_CONSTANT_CACHE",
    "MOP_TO_AST_CACHE",
    # merkle
    "MerkleTree",
    # patching
    "PatchAction",
    "PatchRecorder",
    "BinaryPatcher",
    # ctree_snapshot
    "serialize_ctree",
    "deserialize_ctree",
    "save_ctree_snapshot",
    "load_ctree_snapshot",
    # platform
    "FileFormat",
    "Platform",
    "detect_file_format",
    "detect_platform",
    "get_format_config_keys",
    "is_arch_specific_config",
    "resolve_arch_config",
    "ARCH_CONFIG_KEYS",
]

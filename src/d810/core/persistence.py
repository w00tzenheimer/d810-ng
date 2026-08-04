"""Persistent storage layer for optimization results.

This module provides IDA-independent SQLite-backed storage for:
- Function fingerprints (for cache validation)
- Optimization results and patches
- Scoped function recipes and tags

The storage survives restarts and allows results to be reused across
sessions, dramatically speeding up repeated analysis.

Architecture:
    - Functions table: Stores function metadata and hash
    - Blocks table: Stores block-level def/use information
    - Patches table: Stores optimization transformations
    - FunctionRecipesV2 table: Scoped public pass recipes
    - FunctionTagsV2 table: Scoped internal function metadata
    - Results table: Optimization results per function

Usage:
    storage = SQLiteOptimizationStorage("analysis.db")
    phase = ProviderPhaseSnapshot(
        provider_name="hexrays_microcode",
        provider_level=5,
        friendly_provider_level="MMAT_GLBOPT1",
    )

    # Save results
    storage.save_result(
        function_addr=0x401000,
        fingerprint=fingerprint,
        provider_phase=phase,
        changes=42,
        patches=[...]
    )

    # Load results
    result = storage.load_result(0x401000, provider_phase=phase)
"""

from __future__ import annotations

import json
import sqlite3
import time
import zlib
from dataclasses import dataclass
from pathlib import Path

from d810.core.provider_phase import ProviderPhase
from d810.core.typing import (
    Any,
    Dict,
    Iterator,
    List,
    Optional,
    Protocol,
    Set,
    runtime_checkable,
)

from .logging import getLogger

logger = getLogger(__name__)


@dataclass
class FunctionFingerprint:
    """Fingerprint of a function for cache validation.

    This is IDA-independent - the actual fingerprint computation
    happens in the IDA-aware layer.
    """

    address: int
    size: int
    bytes_hash: str  # SHA-256 of function bytes
    block_count: int
    instruction_count: int


@dataclass
class CachedResult:
    """Cached optimization result for a function."""

    function_addr: int
    provider_name: str
    provider_level: int
    friendly_provider_level: str
    changes_made: int
    patches: List[Dict[str, Any]]
    timestamp: float
    fingerprint: str


@dataclass(frozen=True)
class FunctionStorageLocator:
    """Stable owner and address for durable per-function operator data."""

    database_identity: str
    project_name: str
    function_addr: int


@dataclass(frozen=True)
class FunctionRecipeConfig:
    """Complete registered-pass pipeline saved for one function."""

    locator: FunctionStorageLocator
    schema_version: int
    function_fingerprint: str | None
    source_path: str
    runtime_path: str
    pass_configs_json: str
    updated_at: float

    @property
    def function_addr(self) -> int:
        return self.locator.function_addr


class SupportsOptimizationStorage(Protocol):
    """Common interface for persistence backends."""

    def has_valid_cache(self, function_addr: int, current_hash: str) -> bool: ...
    def save_fingerprint(self, fingerprint: FunctionFingerprint) -> None: ...
    def save_result(
        self,
        function_addr: int,
        fingerprint: FunctionFingerprint,
        provider_phase: ProviderPhase,
        changes: int,
        patches: List[Dict[str, Any]],
    ) -> None: ...
    def load_result(
        self, function_addr: int, provider_phase: ProviderPhase
    ) -> Optional[CachedResult]: ...
    def set_function_recipe(
        self,
        *,
        locator: FunctionStorageLocator,
        schema_version: int,
        function_fingerprint: str | None,
        source_path: str,
        runtime_path: str,
        pass_configs_json: str,
    ) -> None: ...
    def get_function_recipe(
        self, locator: FunctionStorageLocator
    ) -> Optional[FunctionRecipeConfig]: ...
    def clear_function_recipe(self, locator: FunctionStorageLocator) -> None: ...
    def set_function_tags(
        self, locator: FunctionStorageLocator, tags: Set[str]
    ) -> None: ...
    def get_function_tags(self, locator: FunctionStorageLocator) -> Set[str]: ...
    def invalidate_function(self, function_addr: int) -> None: ...
    def get_statistics(self) -> Dict[str, Any]: ...
    def close(self) -> None: ...


NETNODE_BLOB_SIZE = 1024
NETNODE_INT_KEYS_TAG = "M"
NETNODE_STR_KEYS_TAG = "N"
NETNODE_STR_TO_INT_MAP_TAG = "O"
NETNODE_INT_TO_INT_MAP_TAG = "P"


class NetnodeCorruptError(RuntimeError):
    pass


@runtime_checkable
class IDA9NetnodeLike(Protocol):
    def create(self, name: str) -> bool: ...
    def kill(self) -> None: ...
    def supval(self, idx: int, tag: str = ...) -> Optional[bytes]: ...
    def supset(self, idx: int, value: bytes, tag: str = ...) -> bool: ...
    def supdel(self, idx: int, tag: str = ...) -> bool: ...
    def supfirst(self, tag: str = ...) -> int: ...
    def supnext(self, idx: int, tag: str = ...) -> int: ...
    def suplast(self, tag: str = ...) -> int: ...
    def hashval(self, key: str, tag: str = ...) -> Optional[bytes]: ...
    def hashset(self, key: str, value: bytes, tag: str = ...) -> bool: ...
    def hashdel(self, key: str, tag: str = ...) -> bool: ...
    def hashfirst(self, tag: str = ...) -> Any: ...
    def hashnext(self, key: Any, tag: str = ...) -> Any: ...
    def getblob(self, idx: int, tag: str) -> Optional[bytes]: ...
    def setblob(self, value: bytes, idx: int, tag: str) -> bool: ...
    def delblob(self, idx: int, tag: str) -> bool: ...


@runtime_checkable
class IDA9NetnodeModuleLike(Protocol):
    BADNODE: int

    def netnode(self, *args: Any, **kwargs: Any) -> IDA9NetnodeLike: ...


class Netnode:
    """Typed IDA9+ netnode key/value wrapper with compression and blob fallback.

    Keys: ``int`` or ``str``.
    Values: JSON-serializable object (``None`` is not allowed).
    """

    def __init__(
        self,
        netnode_name: str = "$ d810.optimization_storage",
        *,
        module: IDA9NetnodeModuleLike | None = None,
    ):
        self._netnode_name = netnode_name
        self._module = module or self._import_module()
        self._badnode = int(getattr(self._module, "BADNODE", -1))
        self._n = self._open_node()

    @staticmethod
    def _import_module() -> IDA9NetnodeModuleLike:
        try:
            import ida_netnode  # type: ignore
            import idaapi  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "Netnode backend requires IDA9+ runtime (ida_netnode)."
            ) from exc
        try:
            major = int(str(idaapi.get_kernel_version()).split(".", 1)[0])
        except Exception as exc:
            raise RuntimeError(
                "Unable to determine IDA version for netnode backend."
            ) from exc
        if major < 9:
            raise RuntimeError(f"Netnode backend requires IDA 9+, found IDA {major}.")
        return ida_netnode  # type: ignore[return-value]

    def _open_node(self) -> IDA9NetnodeLike:
        node = self._module.netnode()
        if not node.create(self._netnode_name):
            # Re-open existing node by name when create() returns False.
            node = self._module.netnode(self._netnode_name, 0, False)
        return node

    @staticmethod
    def _compress(data: bytes) -> bytes:
        return zlib.compress(data)

    @staticmethod
    def _decompress(data: bytes) -> bytes:
        return zlib.decompress(data)

    @staticmethod
    def _encode(data: Any) -> bytes:
        return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @staticmethod
    def _decode(data: bytes) -> Any:
        return json.loads(data.decode("utf-8"))

    @staticmethod
    def _coerce_int(value: bytes | str | int) -> int:
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="strict")
        return int(value)

    def _is_badnode(self, value: Any) -> bool:
        try:
            return int(value) == self._badnode
        except Exception:
            return False

    def _get_next_slot(self, tag: str) -> int:
        slot = self._n.suplast(tag)
        if slot is None or self._is_badnode(slot):
            return 0
        return int(slot) + 1

    def _intdel(self, key: int) -> None:
        did_del = False
        storekey_raw = self._n.supval(key, NETNODE_INT_TO_INT_MAP_TAG)
        if storekey_raw is not None:
            storekey = self._coerce_int(storekey_raw)
            self._n.delblob(storekey, NETNODE_INT_KEYS_TAG)
            self._n.supdel(key, NETNODE_INT_TO_INT_MAP_TAG)
            did_del = True
        if self._n.supval(key) is not None:
            self._n.supdel(key)
            did_del = True
        if not did_del:
            raise KeyError(f"{key!r} not found")

    def _intset(self, key: int, value: bytes) -> None:
        try:
            self._intdel(key)
        except KeyError:
            pass

        if len(value) > NETNODE_BLOB_SIZE:
            storekey = self._get_next_slot(NETNODE_INT_KEYS_TAG)
            self._n.setblob(value, storekey, NETNODE_INT_KEYS_TAG)
            self._n.supset(
                key,
                str(storekey).encode("utf-8"),
                NETNODE_INT_TO_INT_MAP_TAG,
            )
        else:
            self._n.supset(key, value)

    def _intget(self, key: int) -> bytes:
        storekey_raw = self._n.supval(key, NETNODE_INT_TO_INT_MAP_TAG)
        if storekey_raw is not None:
            storekey = self._coerce_int(storekey_raw)
            value = self._n.getblob(storekey, NETNODE_INT_KEYS_TAG)
            if value is None:
                raise NetnodeCorruptError("Missing int-key blob payload")
            return value
        value = self._n.supval(key)
        if value is not None:
            return value
        raise KeyError(f"{key!r} not found")

    def _strdel(self, key: str) -> None:
        did_del = False
        storekey_raw = self._n.hashval(key, NETNODE_STR_TO_INT_MAP_TAG)
        if storekey_raw is not None:
            storekey = self._coerce_int(storekey_raw)
            self._n.delblob(storekey, NETNODE_STR_KEYS_TAG)
            self._n.hashdel(key, NETNODE_STR_TO_INT_MAP_TAG)
            did_del = True
        if self._n.hashval(key) is not None:
            self._n.hashdel(key)
            did_del = True
        if not did_del:
            raise KeyError(f"{key!r} not found")

    def _strset(self, key: str, value: bytes) -> None:
        try:
            self._strdel(key)
        except KeyError:
            pass

        if len(value) > NETNODE_BLOB_SIZE:
            storekey = self._get_next_slot(NETNODE_STR_KEYS_TAG)
            self._n.setblob(value, storekey, NETNODE_STR_KEYS_TAG)
            self._n.hashset(
                key,
                str(storekey).encode("utf-8"),
                NETNODE_STR_TO_INT_MAP_TAG,
            )
        else:
            self._n.hashset(key, value)

    def _strget(self, key: str) -> bytes:
        storekey_raw = self._n.hashval(key, NETNODE_STR_TO_INT_MAP_TAG)
        if storekey_raw is not None:
            storekey = self._coerce_int(storekey_raw)
            value = self._n.getblob(storekey, NETNODE_STR_KEYS_TAG)
            if value is None:
                raise NetnodeCorruptError("Missing str-key blob payload")
            return value
        value = self._n.hashval(key)
        if value is not None:
            return value
        raise KeyError(f"{key!r} not found")

    def __getitem__(self, key: int | str) -> Any:
        if isinstance(key, str):
            raw = self._strget(key)
        elif isinstance(key, int):
            raw = self._intget(key)
        else:
            raise TypeError(f"unsupported key type: {type(key)!r}")
        return self._decode(self._decompress(raw))

    def __setitem__(self, key: int | str, value: Any) -> None:
        if value is None:
            raise ValueError("netnode values must not be None")
        payload = self._compress(self._encode(value))
        if isinstance(key, str):
            self._strset(key, payload)
            return
        if isinstance(key, int):
            self._intset(key, payload)
            return
        raise TypeError(f"unsupported key type: {type(key)!r}")

    def __delitem__(self, key: int | str) -> None:
        if isinstance(key, str):
            self._strdel(key)
            return
        if isinstance(key, int):
            self._intdel(key)
            return
        raise TypeError(f"unsupported key type: {type(key)!r}")

    def get(self, key: int | str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, zlib.error, ValueError, NetnodeCorruptError):
            return default

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, (str, int)):
            return False
        try:
            self[key]
            return True
        except (KeyError, zlib.error, ValueError, NetnodeCorruptError):
            return False

    def _iter_int_keys_small(self) -> Iterator[int]:
        cursor = self._n.supfirst()
        while not self._is_badnode(cursor):
            yield int(cursor)
            cursor = self._n.supnext(int(cursor))

    def _iter_int_keys_large(self) -> Iterator[int]:
        cursor = self._n.supfirst(NETNODE_INT_TO_INT_MAP_TAG)
        while not self._is_badnode(cursor):
            yield int(cursor)
            cursor = self._n.supnext(int(cursor), NETNODE_INT_TO_INT_MAP_TAG)

    def _iter_str_keys_small(self) -> Iterator[str]:
        cursor = self._n.hashfirst()
        while cursor is not None and not self._is_badnode(cursor):
            yield str(cursor)
            cursor = self._n.hashnext(cursor)

    def _iter_str_keys_large(self) -> Iterator[str]:
        cursor = self._n.hashfirst(NETNODE_STR_TO_INT_MAP_TAG)
        while cursor is not None and not self._is_badnode(cursor):
            yield str(cursor)
            cursor = self._n.hashnext(cursor, NETNODE_STR_TO_INT_MAP_TAG)

    def iterkeys(self) -> Iterator[int | str]:
        seen: set[int | str] = set()
        for key in self._iter_int_keys_small():
            if key not in seen:
                seen.add(key)
                yield key
        for key in self._iter_int_keys_large():
            if key not in seen:
                seen.add(key)
                yield key
        for key in self._iter_str_keys_small():
            if key not in seen:
                seen.add(key)
                yield key
        for key in self._iter_str_keys_large():
            if key not in seen:
                seen.add(key)
                yield key

    def kill(self) -> None:
        self._n.kill()
        self._n = self._open_node()


class NetnodeOptimizationStorage:
    """Netnode-backed storage for optimization results.

    This backend is intended for IDA runtime usage where storing data inside
    the IDB is preferred over external files. It keeps the same high-level API
    as :class:`SQLiteOptimizationStorage`.
    """

    _STATE_KEY = "d810.optimization_storage.v1"

    def __init__(self, node_name: str = "$ d810.optimization_storage"):
        self.node_name = node_name
        self._kv = Netnode(node_name)
        self._state: dict[str, Any] = {
            "functions": {},
            "results": {},
            "patches": {},
            "function_tags_v2": {},
            "function_recipes_v2": {},
        }
        self._state = self._load_state()
        logger.info("Netnode optimization storage initialized: %s", self.node_name)

    def _serialize(self) -> str:
        return json.dumps(self._state, sort_keys=True)

    def _deserialize(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            payload = {}
        payload.setdefault("functions", {})
        payload.setdefault("results", {})
        payload.setdefault("patches", {})
        payload.setdefault("function_tags_v2", {})
        payload.setdefault("function_recipes_v2", {})
        for legacy_key in (
            "function_rules",
            "function_recipes",
            "active_inference",
            "active_recipe",
        ):
            payload.pop(legacy_key, None)
        return payload

    def _load_state(self) -> dict[str, Any]:
        payload = self._kv.get(self._STATE_KEY, None)
        return self._deserialize(payload)

    def _flush_state(self) -> None:
        self._kv[self._STATE_KEY] = self._state

    @staticmethod
    def _result_key(function_addr: int, provider_phase: ProviderPhase) -> str:
        return (
            f"{int(function_addr)}:"
            f"{str(provider_phase.provider_name)}:"
            f"{int(provider_phase.provider_level)}"
        )

    @staticmethod
    def _func_key(function_addr: int) -> str:
        return str(int(function_addr))

    @staticmethod
    def _scoped_key(locator: FunctionStorageLocator) -> str:
        return json.dumps(
            [
                str(locator.database_identity),
                str(locator.project_name),
                int(locator.function_addr),
            ],
            separators=(",", ":"),
        )

    def has_valid_cache(self, function_addr: int, current_hash: str) -> bool:
        entry = self._state["functions"].get(self._func_key(function_addr))
        if not entry:
            return False
        cached_hash = str(entry.get("bytes_hash", ""))
        if cached_hash != current_hash:
            logger.info(
                "Cache invalidated for function %x: fingerprint mismatch",
                function_addr,
            )
            return False
        return True

    def save_fingerprint(self, fingerprint: FunctionFingerprint) -> None:
        now = time.time()
        self._state["functions"][self._func_key(fingerprint.address)] = {
            "address": int(fingerprint.address),
            "size": int(fingerprint.size),
            "bytes_hash": fingerprint.bytes_hash,
            "block_count": int(fingerprint.block_count),
            "instruction_count": int(fingerprint.instruction_count),
            "created_at": now,
            "updated_at": now,
        }
        self._flush_state()

    def save_result(
        self,
        function_addr: int,
        fingerprint: FunctionFingerprint,
        provider_phase: ProviderPhase,
        changes: int,
        patches: List[Dict[str, Any]],
    ) -> None:
        self.save_fingerprint(fingerprint)
        key = self._result_key(function_addr, provider_phase)
        now = time.time()
        self._state["results"][key] = {
            "function_addr": int(function_addr),
            "provider_name": str(provider_phase.provider_name),
            "provider_level": int(provider_phase.provider_level),
            "friendly_provider_level": str(provider_phase.friendly_provider_level),
            "changes_made": int(changes),
            "fingerprint": fingerprint.bytes_hash,
            "timestamp": now,
        }
        self._state["patches"][key] = list(patches)
        self._flush_state()
        logger.info(
            "Saved optimization result for %x at %s phase %s: %d changes, %d patches",
            function_addr,
            provider_phase.provider_name,
            provider_phase.friendly_provider_level,
            changes,
            len(patches),
        )

    def load_result(
        self, function_addr: int, provider_phase: ProviderPhase
    ) -> Optional[CachedResult]:
        key = self._result_key(function_addr, provider_phase)
        result = self._state["results"].get(key)
        if not result:
            return None
        patches = list(self._state["patches"].get(key, []))
        return CachedResult(
            function_addr=int(result["function_addr"]),
            provider_name=str(result["provider_name"]),
            provider_level=int(result["provider_level"]),
            friendly_provider_level=str(result["friendly_provider_level"]),
            changes_made=int(result["changes_made"]),
            patches=patches,
            timestamp=float(result["timestamp"]),
            fingerprint=str(result["fingerprint"]),
        )

    def set_function_recipe(
        self,
        *,
        locator: FunctionStorageLocator,
        schema_version: int,
        function_fingerprint: str | None,
        source_path: str,
        runtime_path: str,
        pass_configs_json: str,
    ) -> None:
        self._state["function_recipes_v2"][self._scoped_key(locator)] = {
            "schema_version": int(schema_version),
            "function_fingerprint": function_fingerprint,
            "source_path": str(source_path),
            "runtime_path": str(runtime_path),
            "pass_configs_json": str(pass_configs_json),
            "updated_at": time.time(),
        }
        self._flush_state()
        logger.info("Updated function recipe for %x", locator.function_addr)

    def get_function_recipe(
        self, locator: FunctionStorageLocator
    ) -> Optional[FunctionRecipeConfig]:
        row = self._state["function_recipes_v2"].get(self._scoped_key(locator))
        if not row:
            return None
        return FunctionRecipeConfig(
            locator=locator,
            schema_version=int(row.get("schema_version", 0)),
            function_fingerprint=row.get("function_fingerprint"),
            source_path=str(row.get("source_path", "")),
            runtime_path=str(row.get("runtime_path", "")),
            pass_configs_json=str(row.get("pass_configs_json", "")),
            updated_at=float(row.get("updated_at", 0.0)),
        )

    def clear_function_recipe(self, locator: FunctionStorageLocator) -> None:
        self._state["function_recipes_v2"].pop(self._scoped_key(locator), None)
        self._flush_state()
        logger.info("Cleared function recipe for %x", locator.function_addr)

    def set_function_tags(
        self, locator: FunctionStorageLocator, tags: Set[str]
    ) -> None:
        self._state["function_tags_v2"][self._scoped_key(locator)] = {
            "tags": sorted(str(tag).strip() for tag in tags if str(tag).strip()),
            "updated_at": time.time(),
        }
        self._flush_state()
        logger.info("Updated function tags for %x", locator.function_addr)

    def get_function_tags(self, locator: FunctionStorageLocator) -> Set[str]:
        row = self._state["function_tags_v2"].get(self._scoped_key(locator))
        if not row:
            return set()
        return set(row.get("tags", []))

    def invalidate_function(self, function_addr: int) -> None:
        fkey = self._func_key(function_addr)
        self._state["functions"].pop(fkey, None)
        stale = [
            rkey
            for rkey, row in self._state["results"].items()
            if int(row.get("function_addr", -1)) == int(function_addr)
        ]
        for rkey in stale:
            self._state["results"].pop(rkey, None)
            self._state["patches"].pop(rkey, None)
        self._flush_state()
        logger.info("Invalidated cache for function %x", function_addr)

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "functions_cached": len(self._state["functions"]),
            "results_cached": len(self._state["results"]),
            "patches_stored": sum(
                len(v) for v in self._state["patches"].values() if isinstance(v, list)
            ),
            "functions_with_recipes": len(self._state["function_recipes_v2"]),
        }

    def close(self) -> None:
        self._flush_state()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_optimization_storage(
    storage_target: str | Path | None,
    *,
    backend: str = "sqlite",
    **kwargs: Any,
) -> SupportsOptimizationStorage:
    """Create a persistence backend instance.

    Args:
        storage_target:
            - sqlite: filesystem path to the DB file.
            - netnode: optional node name override (uses default when None).
        backend: one of ``sqlite`` or ``netnode``.
    """
    name = backend.strip().lower()
    if name == "sqlite":
        if storage_target is None:
            raise ValueError("sqlite backend requires a database path")
        return SQLiteOptimizationStorage(storage_target)
    if name == "netnode":
        node_name = (
            str(storage_target)
            if storage_target is not None
            else str(kwargs.get("node_name", "$ d810.optimization_storage"))
        )
        return NetnodeOptimizationStorage(node_name=node_name)
    raise ValueError(
        f"Unknown persistence backend '{backend}'. Supported: sqlite, netnode."
    )


class SQLiteOptimizationStorage:
    """SQLite-backed storage for optimization results.

    This is the IDA-independent storage layer. It handles:
    1. Function fingerprints (for validation)
    2. Block-level information (def/use lists)
    3. Optimization patches (transformations applied)
    4. Scoped function recipes and tags
    5. Optimization results (for quick lookup)

    Example:
        >>> storage = SQLiteOptimizationStorage("/tmp/analysis.db")
        >>>
        >>> # Check if we have cached results
        >>> if storage.has_valid_cache(func_addr, current_hash):
        ...     result = storage.load_result(func_addr, provider_phase)
        ...     apply_cached_patches(result.patches)
        ... else:
        ...     # Run optimization
        ...     changes = run_optimization(mba)
        ...     storage.save_result(
        ...         func_addr,
        ...         fingerprint,
        ...         provider_phase,
        ...         changes,
        ...         patches,
        ...     )
    """

    def __init__(self, db_path: str | Path):
        """Initialize the storage.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.conn: Optional[sqlite3.Connection] = None
        self._init_database()
        logger.info(f"Optimization storage initialized: {self.db_path}")

    @staticmethod
    def _table_columns(cursor: sqlite3.Cursor, table_name: str) -> Set[str]:
        cursor.execute(f"PRAGMA table_info({table_name})")
        return {str(row["name"]) for row in cursor.fetchall()}

    def _migrate_provider_phase_schema(self, cursor: sqlite3.Cursor) -> None:
        legacy_level_column = "maturity"

        result_columns = self._table_columns(cursor, "results")
        if (
            legacy_level_column in result_columns
            and "provider_level" not in result_columns
        ):
            cursor.execute("ALTER TABLE results RENAME TO results_legacy_phase")
            cursor.execute(
                """
                CREATE TABLE results (
                    function_addr INTEGER NOT NULL,
                    provider_name TEXT NOT NULL,
                    provider_level INTEGER NOT NULL,
                    friendly_provider_level TEXT NOT NULL,
                    changes_made INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    PRIMARY KEY (function_addr, provider_name, provider_level),
                    FOREIGN KEY (function_addr) REFERENCES functions(address)
                )
            """
            )
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO results
                (
                    function_addr,
                    provider_name,
                    provider_level,
                    friendly_provider_level,
                    changes_made,
                    fingerprint,
                    timestamp
                )
                SELECT
                    function_addr,
                    'hexrays_microcode',
                    {legacy_level_column},
                    CAST({legacy_level_column} AS TEXT),
                    changes_made,
                    fingerprint,
                    timestamp
                FROM results_legacy_phase
            """
            )
            cursor.execute("DROP TABLE results_legacy_phase")

        patch_columns = self._table_columns(cursor, "patches")
        if (
            legacy_level_column in patch_columns
            and "provider_level" not in patch_columns
        ):
            cursor.execute("ALTER TABLE patches RENAME TO patches_legacy_phase")
            cursor.execute(
                """
                CREATE TABLE patches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    function_addr INTEGER NOT NULL,
                    provider_name TEXT NOT NULL,
                    provider_level INTEGER NOT NULL,
                    patch_type TEXT NOT NULL,
                    patch_data TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (function_addr) REFERENCES functions(address)
                )
            """
            )
            cursor.execute(
                f"""
                INSERT INTO patches
                (
                    id,
                    function_addr,
                    provider_name,
                    provider_level,
                    patch_type,
                    patch_data,
                    created_at
                )
                SELECT
                    id,
                    function_addr,
                    'hexrays_microcode',
                    {legacy_level_column},
                    patch_type,
                    patch_data,
                    created_at
                FROM patches_legacy_phase
            """
            )
            cursor.execute("DROP TABLE patches_legacy_phase")

    def _init_database(self) -> None:
        """Initialize the database schema."""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        cursor = self.conn.cursor()

        # Functions table: stores function metadata and fingerprints
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS functions (
                address INTEGER PRIMARY KEY,
                size INTEGER NOT NULL,
                bytes_hash TEXT NOT NULL,
                block_count INTEGER NOT NULL,
                instruction_count INTEGER NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """
        )

        # Blocks table: stores block-level def/use information
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                function_addr INTEGER NOT NULL,
                block_serial INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                use_list TEXT,  -- JSON array
                def_list TEXT,  -- JSON array
                PRIMARY KEY (function_addr, block_serial),
                FOREIGN KEY (function_addr) REFERENCES functions(address)
            )
        """
        )

        # Patches table: stores optimization transformations
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                function_addr INTEGER NOT NULL,
                provider_name TEXT NOT NULL,
                provider_level INTEGER NOT NULL,
                patch_type TEXT NOT NULL,  -- 'redirect_edge', 'insert_block', etc.
                patch_data TEXT NOT NULL,  -- JSON
                created_at REAL NOT NULL,
                FOREIGN KEY (function_addr) REFERENCES functions(address)
            )
        """
        )

        # Remove the obsolete operator-authored private-rule model. Its rows are
        # intentionally not adopted because no database/project identity was
        # recorded and ownership cannot be proven.
        cursor.execute("DROP TABLE IF EXISTS function_rules")
        cursor.execute("DROP TABLE IF EXISTS function_recipes")
        cursor.execute("DROP TABLE IF EXISTS rule_scope_inference")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS function_tags_v2 (
                database_identity TEXT NOT NULL,
                project_name TEXT NOT NULL,
                function_addr INTEGER NOT NULL,
                tags TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (database_identity, project_name, function_addr)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS function_recipes_v2 (
                database_identity TEXT NOT NULL,
                project_name TEXT NOT NULL,
                function_addr INTEGER NOT NULL,
                schema_version INTEGER NOT NULL,
                function_fingerprint TEXT,
                source_path TEXT NOT NULL,
                runtime_path TEXT NOT NULL,
                pass_configs_json TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (database_identity, project_name, function_addr)
            )
        """
        )

        # Results table: cached optimization results
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS results (
                function_addr INTEGER NOT NULL,
                provider_name TEXT NOT NULL,
                provider_level INTEGER NOT NULL,
                friendly_provider_level TEXT NOT NULL,
                changes_made INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                timestamp REAL NOT NULL,
                PRIMARY KEY (function_addr, provider_name, provider_level),
                FOREIGN KEY (function_addr) REFERENCES functions(address)
            )
        """
        )

        self._migrate_provider_phase_schema(cursor)

        # Create indices for faster lookups
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_patches_function
            ON patches(function_addr, provider_name, provider_level)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_results_function
            ON results(function_addr, provider_name, provider_level)
        """
        )

        self.conn.commit()
        logger.debug("Database schema initialized")

    def has_valid_cache(self, function_addr: int, current_hash: str) -> bool:
        """Check if we have a valid cache entry for a function.

        Args:
            function_addr: Function address.
            current_hash: Current fingerprint hash to compare against.

        Returns:
            True if cache is valid and can be used.
        """
        if not self.conn:
            return False

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT bytes_hash FROM functions WHERE address = ?", (function_addr,)
        )
        row = cursor.fetchone()

        if not row:
            return False

        # Check if hash matches
        cached_hash = row["bytes_hash"]
        if cached_hash != current_hash:
            logger.info(
                f"Cache invalidated for function {function_addr:x}: "
                "fingerprint mismatch"
            )
            return False

        return True

    def save_fingerprint(self, fingerprint: FunctionFingerprint) -> None:
        """Save a function fingerprint.

        Args:
            fingerprint: The function fingerprint to save.
        """
        if not self.conn:
            return

        timestamp = time.time()
        cursor = self.conn.cursor()

        # Upsert function metadata
        cursor.execute(
            """
            INSERT OR REPLACE INTO functions
            (address, size, bytes_hash, block_count, instruction_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                fingerprint.address,
                fingerprint.size,
                fingerprint.bytes_hash,
                fingerprint.block_count,
                fingerprint.instruction_count,
                timestamp,
                timestamp,
            ),
        )

        self.conn.commit()

    def save_result(
        self,
        function_addr: int,
        fingerprint: FunctionFingerprint,
        provider_phase: ProviderPhase,
        changes: int,
        patches: List[Dict[str, Any]],
    ) -> None:
        """Save optimization result to storage.

        Args:
            function_addr: Function address.
            fingerprint: Function fingerprint.
            provider_phase: Provider-specific optimization phase.
            changes: Number of changes made.
            patches: List of patch descriptions.
        """
        if not self.conn:
            return

        timestamp = time.time()
        cursor = self.conn.cursor()

        # Save fingerprint first
        self.save_fingerprint(fingerprint)

        # Save result
        cursor.execute(
            """
            INSERT OR REPLACE INTO results
            (
                function_addr,
                provider_name,
                provider_level,
                friendly_provider_level,
                changes_made,
                fingerprint,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                function_addr,
                provider_phase.provider_name,
                provider_phase.provider_level,
                provider_phase.friendly_provider_level,
                changes,
                fingerprint.bytes_hash,
                timestamp,
            ),
        )

        # Delete old patches for this function/provider phase combo
        cursor.execute(
            """
            DELETE FROM patches
            WHERE function_addr = ? AND provider_name = ? AND provider_level = ?
        """,
            (
                function_addr,
                provider_phase.provider_name,
                provider_phase.provider_level,
            ),
        )

        # Save new patches
        for patch in patches:
            cursor.execute(
                """
                INSERT INTO patches
                (
                    function_addr,
                    provider_name,
                    provider_level,
                    patch_type,
                    patch_data,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    function_addr,
                    provider_phase.provider_name,
                    provider_phase.provider_level,
                    patch.get("type", "unknown"),
                    json.dumps(patch),
                    timestamp,
                ),
            )

        self.conn.commit()
        logger.info(
            f"Saved optimization result for {function_addr:x} "
            f"at {provider_phase.provider_name} phase "
            f"{provider_phase.friendly_provider_level}: "
            f"{changes} changes, {len(patches)} patches"
        )

    def load_result(
        self, function_addr: int, provider_phase: ProviderPhase
    ) -> Optional[CachedResult]:
        """Load cached optimization result.

        Args:
            function_addr: Function address.
            provider_phase: Provider-specific optimization phase.

        Returns:
            Cached result if found, None otherwise.
        """
        if not self.conn:
            return None

        cursor = self.conn.cursor()

        # Load result
        cursor.execute(
            """
            SELECT
                changes_made,
                fingerprint,
                timestamp
            FROM results
            WHERE function_addr = ? AND provider_name = ? AND provider_level = ?
        """,
            (
                function_addr,
                provider_phase.provider_name,
                provider_phase.provider_level,
            ),
        )

        row = cursor.fetchone()
        if not row:
            return None

        # Load patches
        cursor.execute(
            """
            SELECT patch_type, patch_data
            FROM patches
            WHERE function_addr = ? AND provider_name = ? AND provider_level = ?
            ORDER BY id
        """,
            (
                function_addr,
                provider_phase.provider_name,
                provider_phase.provider_level,
            ),
        )

        patches = [json.loads(r["patch_data"]) for r in cursor.fetchall()]

        logger.info(
            f"Loaded cached result for {function_addr:x} "
            f"at {provider_phase.provider_name} phase "
            f"{provider_phase.friendly_provider_level}: {row['changes_made']} changes"
        )

        return CachedResult(
            function_addr=function_addr,
            provider_name=provider_phase.provider_name,
            provider_level=provider_phase.provider_level,
            friendly_provider_level=provider_phase.friendly_provider_level,
            changes_made=row["changes_made"],
            patches=patches,
            timestamp=row["timestamp"],
            fingerprint=row["fingerprint"],
        )

    def set_function_recipe(
        self,
        *,
        locator: FunctionStorageLocator,
        schema_version: int,
        function_fingerprint: str | None,
        source_path: str,
        runtime_path: str,
        pass_configs_json: str,
    ) -> None:
        if not self.conn:
            return
        self.conn.execute(
            """
            INSERT OR REPLACE INTO function_recipes_v2
            (database_identity, project_name, function_addr, schema_version,
             function_fingerprint, source_path, runtime_path, pass_configs_json,
             updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(locator.database_identity),
                str(locator.project_name),
                int(locator.function_addr),
                int(schema_version),
                function_fingerprint,
                str(source_path),
                str(runtime_path),
                str(pass_configs_json),
                time.time(),
            ),
        )
        self.conn.commit()
        logger.info("Updated function recipe for %x", locator.function_addr)

    def get_function_recipe(
        self, locator: FunctionStorageLocator
    ) -> Optional[FunctionRecipeConfig]:
        if not self.conn:
            return None
        row = self.conn.execute(
            """
            SELECT schema_version, function_fingerprint, source_path,
                   runtime_path, pass_configs_json, updated_at
            FROM function_recipes_v2
            WHERE database_identity = ? AND project_name = ? AND function_addr = ?
            """,
            (
                str(locator.database_identity),
                str(locator.project_name),
                int(locator.function_addr),
            ),
        ).fetchone()
        if row is None:
            return None
        return FunctionRecipeConfig(
            locator=locator,
            schema_version=int(row["schema_version"]),
            function_fingerprint=row["function_fingerprint"],
            source_path=str(row["source_path"]),
            runtime_path=str(row["runtime_path"]),
            pass_configs_json=str(row["pass_configs_json"]),
            updated_at=float(row["updated_at"]),
        )

    def clear_function_recipe(self, locator: FunctionStorageLocator) -> None:
        if not self.conn:
            return
        self.conn.execute(
            """DELETE FROM function_recipes_v2
            WHERE database_identity = ? AND project_name = ? AND function_addr = ?""",
            (
                str(locator.database_identity),
                str(locator.project_name),
                int(locator.function_addr),
            ),
        )
        self.conn.commit()
        logger.info("Cleared function recipe for %x", locator.function_addr)

    def set_function_tags(
        self, locator: FunctionStorageLocator, tags: Set[str]
    ) -> None:
        if not self.conn:
            return
        normalized_tags = {str(tag).strip() for tag in tags if str(tag).strip()}

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO function_tags_v2
            (database_identity, project_name, function_addr, tags, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                str(locator.database_identity),
                str(locator.project_name),
                int(locator.function_addr),
                json.dumps(list(normalized_tags)),
                time.time(),
            ),
        )
        self.conn.commit()
        logger.info("Updated function tags for %x", locator.function_addr)

    def get_function_tags(self, locator: FunctionStorageLocator) -> Set[str]:
        if not self.conn:
            return set()
        row = self.conn.execute(
            """SELECT tags FROM function_tags_v2
            WHERE database_identity = ? AND project_name = ? AND function_addr = ?""",
            (
                str(locator.database_identity),
                str(locator.project_name),
                int(locator.function_addr),
            ),
        ).fetchone()
        if not row:
            return set()
        return set(json.loads(row["tags"] or "[]"))

    def invalidate_function(self, function_addr: int) -> None:
        """Invalidate all cached data for a function.

        Use this when you know a function has changed or want to
        force re-optimization.

        Args:
            function_addr: Function address.
        """
        if not self.conn:
            return

        cursor = self.conn.cursor()

        cursor.execute("DELETE FROM results WHERE function_addr = ?", (function_addr,))
        cursor.execute("DELETE FROM patches WHERE function_addr = ?", (function_addr,))
        cursor.execute("DELETE FROM blocks WHERE function_addr = ?", (function_addr,))
        cursor.execute("DELETE FROM functions WHERE address = ?", (function_addr,))

        self.conn.commit()
        logger.info(f"Invalidated cache for function {function_addr:x}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get storage statistics.

        Returns:
            Dictionary with storage statistics.
        """
        if not self.conn:
            return {}

        cursor = self.conn.cursor()

        stats = {}

        cursor.execute("SELECT COUNT(*) as count FROM functions")
        stats["functions_cached"] = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM results")
        stats["results_cached"] = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM patches")
        stats["patches_stored"] = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM function_recipes_v2")
        stats["functions_with_recipes"] = cursor.fetchone()["count"]

        return stats

    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.debug("Storage database closed")

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support."""
        self.close()

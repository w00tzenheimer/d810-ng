import collections
import dataclasses
import functools
import json
import logging
import logging.config
import pathlib
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime

from d810.core import typing
from d810.core.typing import Any, Dict, List, Protocol, Union, cast, runtime_checkable

LOG_FILENAME = "d810.log"
Z3_TEST_FILENAME = "z3_check_instructions_substitution.py"
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
WARN = logging.WARN
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL
NOTSET = logging.NOTSET
FATAL = logging.FATAL

_config = collections.Counter(version=0)


@dataclasses.dataclass(slots=True)
class LevelFlag:
    """
    LevelFlag provides a fast, zero-allocation cached boolean check for whether a logger is
    enabled for a given level.

    It avoids repeated calls to logger.isEnabledFor(level) in performance-critical code, and automatically
    refreshes its cache when logging configuration changes.

    See: https://docs.python.org/3/howto/logging.html#optimization

    Example:
        logger = logging.getLogger("...")  # any logger
        debug_on = LevelFlag(logger.name, logging.DEBUG)

        # In a hot loop:
        if debug_on:
            do_expensive_debug_stuff()
    """

    _logger_name: str
    _level: int
    _last_version: int = dataclasses.field(default=-1, init=False)
    _cached: bool = dataclasses.field(default=False, init=False)

    def __bool__(self) -> bool:
        current = self.get_config_version()
        if self._last_version != current:
            # config changed (or first call) -> re-compute once
            self._cached = getLogger(self._logger_name).isEnabledFor(self._level)
            self._last_version = current
        return self._cached

    def __repr__(self):
        lvlname = logging.getLevelName(self._level)
        return f"<LevelFlag {self._logger_name}>={lvlname}>"

    @staticmethod
    def bump_config_version() -> None:
        _config["version"] += 1

    @staticmethod
    def get_config_version() -> int:
        return _config["version"]


@runtime_checkable
class D810LoggerProtocol(Protocol):
    """Structural contract for logger instances with D810 MDC extensions."""

    name: str
    level: int
    handlers: list[logging.Handler]
    filters: list[logging.Filter]
    propagate: bool
    disabled: bool
    parent: logging.Logger | None

    @property
    def debug_on(self) -> LevelFlag: ...

    @property
    def info_on(self) -> LevelFlag: ...

    @property
    def warning_on(self) -> LevelFlag: ...

    @property
    def error_on(self) -> LevelFlag: ...

    @property
    def critical_on(self) -> LevelFlag: ...

    @classmethod
    def mdc(cls) -> typing.Mapping[str, typing.Any]: ...

    @classmethod
    def set_mdc(cls, d: dict[str, typing.Any]) -> None: ...

    @classmethod
    def add_mdc(cls, key: str, value: typing.Any) -> None: ...

    @classmethod
    def get_mdc(cls, key: str, default: typing.Any | None = None): ...

    @classmethod
    def remove_mdc(cls, key: str) -> None: ...

    @classmethod
    def clean_mdc(cls) -> None: ...

    @classmethod
    def update_maturity(cls, maturity: str) -> None: ...

    @classmethod
    def reset_maturity(cls) -> None: ...


class D810Logger(logging.Logger):
    """Custom logger that supports a per-thread Mapped Diagnostic Context (MDC)."""

    _mdc_local: "threading.local" = threading.local()

    @classmethod
    def mdc(cls) -> typing.Mapping[str, typing.Any]:
        if not getattr(cls._mdc_local, "mdc", None):
            cls.set_mdc({"maturity": ""})
        return getattr(cls._mdc_local, "mdc", {})

    @classmethod
    def set_mdc(cls, d: dict[str, typing.Any]) -> None:
        cls._mdc_local.mdc = d

    # ------------------------------------------------------------------
    # Quick level checks (cached)
    # ------------------------------------------------------------------
    @functools.cached_property
    def debug_on(self) -> LevelFlag:  # noqa: D401
        """Fast flag: is DEBUG enabled for this logger?"""
        return LevelFlag(self.name, logging.DEBUG)

    @functools.cached_property
    def info_on(self) -> LevelFlag:  # noqa: D401
        return LevelFlag(self.name, logging.INFO)

    @functools.cached_property
    def warning_on(self) -> LevelFlag:  # noqa: D401
        return LevelFlag(self.name, logging.WARNING)

    @functools.cached_property
    def error_on(self) -> LevelFlag:  # noqa: D401
        return LevelFlag(self.name, logging.ERROR)

    @functools.cached_property
    def critical_on(self) -> LevelFlag:  # noqa: D401
        return LevelFlag(self.name, logging.CRITICAL)

    # ---------------------------------------------------------------------
    # MDC helpers
    # ---------------------------------------------------------------------
    @classmethod
    def add_mdc(cls, key: str, value: typing.Any) -> None:
        """Add or update a key/value pair to the thread-local MDC."""
        d = dict(cls.mdc())
        d[key] = value
        cls.set_mdc(d)

    @classmethod
    def get_mdc(cls, key: str, default: typing.Any | None = None):
        """Return the value stored under *key* in the MDC (or *default*)."""
        return cls.mdc().get(key, default)

    @classmethod
    def remove_mdc(cls, key: str) -> None:
        """Remove *key* from the MDC if present."""
        d = dict(cls.mdc())
        d.pop(key, None)
        cls.set_mdc(d)

    @classmethod
    def clean_mdc(cls) -> None:
        """Clear the MDC for the current thread."""
        cls.set_mdc({})

    # Convenience: store current Hex-Rays maturity in MDC so formatters can
    # include it in every record.
    @classmethod
    def update_maturity(cls, maturity: str) -> None:
        cls.add_mdc("maturity", maturity)

    @classmethod
    def reset_maturity(cls) -> None:
        cls.remove_mdc("maturity")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def makeRecord(
        self,
        name,
        level,
        fn,
        lno,
        msg,
        args,
        exc_info,
        func=None,
        extra: dict[str, typing.Any] | None = None,
        sinfo=None,
    ):
        """Inject the current MDC into every ``LogRecord`` that we create."""
        if not extra:
            extra = {}
        extra.update(self.mdc())
        return super().makeRecord(
            name,
            level,
            fn,
            lno,
            msg,
            args,
            exc_info,
            func=func,
            extra=extra,
            sinfo=sinfo,
        )


class D810Formatter(logging.Formatter):
    """Custom formatter that makes MDC key/values directly addressable in format strings."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        # mdc = getattr(record, "mdc", None)
        # if isinstance(mdc, dict):
        #     # Expose MDC keys as attributes so %(key)s works in format strings.
        #     for k, v in mdc.items():
        #         if not hasattr(record, k):
        #             setattr(record, k, v)
        # Ensure 'maturity' placeholder always resolves
        maturity = getattr(record, "maturity", "")
        if maturity:
            record.maturity = f" - {maturity}"
        else:
            record.maturity = ""

        return super().format(record)


# File paths for handlers are set to `None` initially and will be populated
# by the `configure_loggers` function.
conf: dict[str, typing.Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "D810Formatter": {
            "()": D810Formatter,
            "format": "%(asctime)s - %(name)s - %(levelname)s%(maturity)s - %(message)s",
        },
        "rawFormatter": {
            "format": "%(message)s",
        },
    },
    "handlers": {
        "consoleHandler": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "D810Formatter",
            "stream": "ext://sys.stdout",  # Modern way to specify stdout
        },
        "defaultFileHandler": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "D810Formatter",
            "filename": None,  # Placeholder, will be set dynamically
        },
        "z3FileHandler": {
            "class": "logging.FileHandler",
            "level": "INFO",
            "formatter": "rawFormatter",
            "filename": None,  # Placeholder, will be set dynamically
        },
    },
    "loggers": {
        "D810": {
            "level": "INFO",
            "handlers": ["consoleHandler", "defaultFileHandler"],
            "propagate": False,
        },
        "D810.ui": {
            "level": "ERROR",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.optimizer": {
            "level": "INFO",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.chain": {
            "level": "INFO",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.branch_fixer": {
            "level": "INFO",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.unflat": {
            "level": "INFO",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.tracker": {
            "level": "INFO",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.emulator": {
            "level": "WARNING",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.helper": {
            "level": "INFO",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.pattern_search": {
            "level": "INFO",
            "handlers": ["defaultFileHandler"],
            "propagate": False,
        },
        "D810.z3_test": {
            "level": "INFO",
            "handlers": ["z3FileHandler"],
            "propagate": False,
        },
    },
    "root": {
        "level": "DEBUG",
        "handlers": ["consoleHandler", "defaultFileHandler"],
    },
}


# # Ensure *every* LogRecord, no matter the logger class, carries MDC data so
# # that format strings with "%(maturity)s" never raise a KeyError.
# _old_factory = logging.getLogRecordFactory()

# def _d810_record_factory(*args, **kwargs):  # type: ignore
#     record = _old_factory(*args, **kwargs)
#     # Inject MDC data for non-D810Logger records
#     if not hasattr(record, "mdc"):
#         # Fetch MDC from the logger instance if available; else empty dict.
#         try:
#             logger_obj = logging.getLogger(record.name)
#             if isinstance(logger_obj, D810LoggerProtocol):
#                 record.mdc = (
#                     logger_obj._get_mdc()
#                 )  # pylint: disable=protected-access
#             else:
#                 record.mdc = {}
#         except Exception:
#             record.mdc = {}
#     return record

# logging.setLogRecordFactory(_d810_record_factory)


class LoggerConfigurator:
    """
    Utility to dynamically query and set logger levels at runtime.
    """

    @staticmethod
    def available_loggers(
        prefix: str | typing.Iterable[str] | None = None,
        case_insensitive: bool = False,
    ) -> list[str]:
        """
        Return a deduped, sorted list of all logger names, with optional prefix filtering.

        - Any module that's been imported and that did getLogger(__name__) will show up under dyn.
        - Any logger statically declared in conf["loggers"] shows up under stat.
        - If `prefix` is provided, filter to names equal to or starting with prefix + '.'.
        - If `prefix` is a list or other iterable, match any of the prefixes.
        - If `case_insensitive` is True, perform case-insensitive matching.
        """
        mgr = logging.Logger.manager
        # 1) dynamic ones
        dyn = {
            name
            for name, logger in mgr.loggerDict.items()
            # ast-grep-ignore: no-concrete-isinstance
            if isinstance(logger, logging.Logger)
        }
        # 2) static ones from your dictConfig
        stat = set(conf["loggers"].keys())

        all_names = dyn | stat

        if prefix is None:
            return sorted(all_names)

        if isinstance(prefix, str):
            prefixes = [prefix]
        else:
            prefixes = list(prefix)

        if case_insensitive:
            prefixes = [p.lower() for p in prefixes]

            def match(name: str) -> bool:
                lname = name.lower()
                return any(lname == p or lname.startswith(p + ".") for p in prefixes)

        else:

            def match(name: str) -> bool:
                return any(name == p or name.startswith(p + ".") for p in prefixes)

        filtered = filter(match, all_names)
        return sorted(filtered)

    @staticmethod
    def get_level(name: str) -> int:
        """Return the effective level for logger `name`."""
        return getLogger(name).getEffectiveLevel()

    @staticmethod
    def set_level(logger_name: str, level_name: str) -> None:
        """
        Change the level for `logger_name` to one of DEBUG, INFO, WARNING, ERROR, CRITICAL.
        """
        lvl = getattr(logging, level_name.upper(), None)
        if lvl is None:
            raise ValueError(f"Unknown logging level: {level_name}")
        # print(f"Setting level for {logger_name} to {level_name}")
        getLogger(logger_name, lvl).setLevel(lvl)
        # invalidate all LevelFlags
        LevelFlag.bump_config_version()


def clear_logs(log_dir: str | pathlib.Path) -> None:
    """Removes the log directory."""
    shutil.rmtree(log_dir, ignore_errors=True)


def configure_loggers(log_dir: str | pathlib.Path) -> None:
    """
    Configures the loggers using a dictionary, creating log files in the specified directory.
    """
    log_dir = pathlib.Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    # Dynamically set the filenames in the configuration dictionary.
    # This replaces the `defaults` mechanism from fileConfig.
    conf["handlers"]["defaultFileHandler"]["filename"] = (
        log_dir / LOG_FILENAME
    ).as_posix()
    conf["handlers"]["z3FileHandler"]["filename"] = (
        log_dir / Z3_TEST_FILENAME
    ).as_posix()

    # Apply the configuration
    logging.config.dictConfig(conf)

    z3_file_logger = logging.getLogger("D810.z3_test")
    z3_file_logger.info(
        "from z3 import BitVec, BitVecVal, UDiv, URem, LShR, UGT, UGE, ULT, ULE, prove\n\n"
    )
    LevelFlag.bump_config_version()


def getLogger(name: str, default_level: int = logging.INFO) -> D810Logger:
    """Return a :class:`D810Logger`.

    Extra safety:

    1. If the root logger has *no* handlers we assume logging was never
       configured and transparently invoke :pyfunc:`configure_loggers` with a
       sensible default directory.  This makes interactive sessions like

       >>> from d810.core import getLogger
       >>> log = getLogger("d810.expr.ast")

       work without the user having to remember to call
       :pyfunc:`configure_loggers` first.

    2. When wrapping an existing logger whose ``propagate`` flag is *False*
       **and** that has **no handlers**, the record would be lost.  We flip
       ``propagate`` back to *True* so that messages bubble to the root
       handlers configured above.
    """

    name = name or __name__
    # grab (or create) the underlying Logger
    base = logging.getLogger(name)
    # if it's already the right type, just return it
    if isinstance(base, D810LoggerProtocol):
        return cast(D810Logger, base)
    # otherwise wrap it in the subclass
    loglvl = base.level
    if loglvl == logging.NOTSET or loglvl < default_level:
        loglvl = default_level
    new = D810Logger(base.name, level=loglvl)
    # copy over handlers/filters/propagate flag
    new.handlers = list(base.handlers)
    new.filters = list(base.filters)
    new.propagate = base.propagate
    new.disabled = base.disabled
    # Preserve the hierarchical parent so that records still bubble up to
    # root handlers; otherwise ``p.parent is None`` and nothing is emitted
    # when the logger itself has no handlers.
    new.parent = base.parent
    # Avoid silent drops: if the logger neither has handlers nor propagates
    # up the hierarchy, re-enable propagation so the record reaches root.
    if not new.handlers and not new.propagate:
        new.propagate = True

    # replace it in the manager so future getLogger(...) calls return the subclass
    logging.Logger.manager.loggerDict[name] = new
    return new


# =============================================================================
# SQLite-based structured logging backend (merged from structured_logging.py)
# =============================================================================


class SQLiteHandler(logging.Handler):
    """
    A logging handler that writes records to a SQLite database.

    Thread-safe implementation using a lock for database operations.
    """

    # Standard LogRecord attributes to exclude from extra field
    STANDARD_ATTRS = {
        "name",
        "msg",
        "args",
        "created",
        "msecs",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "lineno",
        "funcName",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "relativeCreated",
        "exc_info",
        "exc_text",
        "stack_info",
        "asctime",
    }

    def __init__(self, db_path: str, test_id: str = None):
        """
        Initialize SQLite logging handler.

        Args:
            db_path: Path to SQLite database file.
            test_id: Optional test identifier for correlating logs.
        """
        super().__init__()
        self.db_path = db_path
        self.test_id = test_id
        self._lock = threading.Lock()

        # Ensure parent directory exists
        pathlib.Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize database schema
        self._init_schema()

    def _init_schema(self):
        """Create the database schema if it doesn't exist."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        logger TEXT NOT NULL,
                        level TEXT NOT NULL,
                        levelno INTEGER NOT NULL,
                        function TEXT,
                        lineno INTEGER,
                        pathname TEXT,
                        message TEXT NOT NULL,
                        extra JSON,
                        test_id TEXT
                    )
                """
                )

                # Create indexes for common queries
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_logs_logger ON logs(logger)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_logs_test_id ON logs(test_id)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)"
                )

                conn.commit()
            finally:
                conn.close()

    def emit(self, record: logging.LogRecord):
        """
        Write a log record to the database.

        Args:
            record: The log record to write.
        """
        try:
            # Format timestamp as ISO 8601
            timestamp = datetime.fromtimestamp(record.created).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )

            # Extract extra fields
            extra = {}
            for key, value in record.__dict__.items():
                if key not in self.STANDARD_ATTRS:
                    try:
                        # Ensure value is JSON serializable
                        json.dumps(value)
                        extra[key] = value
                    except (TypeError, ValueError):
                        # If not serializable, convert to string
                        extra[key] = str(value)

            # Serialize extra as JSON string, or None if empty
            extra_json = json.dumps(extra) if extra else None

            # Get formatted message
            msg = self.format(record)

            # Insert record into database
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO logs (
                            timestamp, logger, level, levelno, function,
                            lineno, pathname, message, extra, test_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            timestamp,
                            record.name,
                            record.levelname,
                            record.levelno,
                            record.funcName,
                            record.lineno,
                            record.pathname,
                            msg,
                            extra_json,
                            self.test_id,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()

        except Exception:
            # Don't raise exceptions from emit() - log handler errors shouldn't crash the app
            pass

    def close(self):
        """Close the handler (no persistent connection to close)."""
        super().close()


@contextmanager
def debug_scope(
    loggers: Union[List[str], str] = "d810",
    db_path: str = ".d810_debug.db",
    test_id: str = None,
    level: int = logging.DEBUG,
):
    """
    Context manager that temporarily enables DEBUG logging to SQLite.

    Usage:
        with debug_scope(
            loggers=['d810.hexrays.tracker'],
            db_path='test.db',
            test_id='test_abc_f6'
        ):
            # Code here has DEBUG logging captured to SQLite
            result = some_function()

        # After scope: logs in SQLite, original levels restored

    Args:
        loggers: Logger name(s) to enable debug for. Can be single string or list.
        db_path: Path to SQLite database file.
        test_id: Optional test identifier for correlating logs.
        level: Log level to set (default DEBUG).

    Yields:
        SQLiteHandler instance (for querying db_path after scope)
    """
    # Normalize loggers to list
    if isinstance(loggers, str):
        loggers = [loggers]

    # Create SQLite handler
    handler = SQLiteHandler(db_path, test_id)
    handler.setLevel(level)

    # Store original levels and handlers
    original_state = []

    try:
        # Configure each logger
        for logger_name in loggers:
            logger = logging.getLogger(logger_name)

            # Store original state
            original_state.append(
                {
                    "logger": logger,
                    "level": logger.level,
                    "propagate": logger.propagate,
                    "handlers": logger.handlers.copy(),
                }
            )

            # Set new level and add handler
            logger.setLevel(level)
            logger.addHandler(handler)

        # Yield the handler for potential use
        yield handler

    finally:
        # Restore original state
        for state in original_state:
            logger = state["logger"]
            logger.setLevel(state["level"])
            logger.removeHandler(handler)

        # Close the handler
        handler.close()


def query_logs(
    db_path: str,
    logger: str = None,
    test_id: str = None,
    level: str = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    Query logs from SQLite database.

    Args:
        db_path: Path to SQLite database file.
        logger: Optional logger name to filter by.
        test_id: Optional test ID to filter by.
        level: Optional log level to filter by.
        limit: Maximum number of records to return.

    Returns:
        List of dicts with log record fields.
    """
    # Build query with filters
    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if logger:
        query += " AND logger = ?"
        params.append(logger)

    if test_id:
        query += " AND test_id = ?"
        params.append(test_id)

    if level:
        query += " AND level = ?"
        params.append(level)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    # Execute query
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Enable column access by name

    try:
        cursor = conn.cursor()
        cursor.execute(query, params)

        # Convert rows to dicts
        results = []
        for row in cursor.fetchall():
            record = dict(row)
            # Deserialize extra field if present
            if record.get("extra"):
                try:
                    record["extra"] = json.loads(record["extra"])
                except json.JSONDecodeError:
                    pass  # Leave as string if not valid JSON
            results.append(record)

        # Return in chronological order (we selected in reverse)
        return results[::-1]

    finally:
        conn.close()

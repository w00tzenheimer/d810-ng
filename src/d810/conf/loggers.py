import collections
import dataclasses
import logging
import logging.config
import pathlib
import shutil
import typing

LOG_FILENAME = "d810.log"
Z3_TEST_FILENAME = "z3_check_instructions_substitution.py"

# File paths for handlers are set to `None` initially and will be populated
# by the `configure_loggers` function.
conf: dict[str, typing.Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "defaultFormatter": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
        "rawFormatter": {
            "format": "%(message)s",
        },
    },
    "handlers": {
        "consoleHandler": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "defaultFormatter",
            "stream": "ext://sys.stdout",  # Modern way to specify stdout
        },
        "defaultFileHandler": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "defaultFormatter",
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
        "level": "INFO",
        "handlers": ["consoleHandler"],
    },
}


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
            # config changed (or first call) → re-compute once
            self._cached = logging.getLogger(self._logger_name).isEnabledFor(
                self._level
            )
            self._last_version = current
        return self._cached

    def __repr__(self):
        lvlname = logging.getLevelName(self._level)
        return f"<LevelFlag {self._logger_name}≥{lvlname}>"

    @staticmethod
    def bump_config_version() -> None:
        _config["version"] += 1

    @staticmethod
    def get_config_version() -> int:
        return _config["version"]


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
        return logging.getLogger(name).getEffectiveLevel()

    @staticmethod
    def set_level(logger_name: str, level_name: str) -> None:
        """
        Change the level for `logger_name` to one of DEBUG, INFO, WARNING, ERROR, CRITICAL.
        """
        lvl = getattr(logging, level_name.upper(), None)
        if lvl is None:
            raise ValueError(f"Unknown logging level: {level_name}")
        logging.getLogger(logger_name).setLevel(lvl)
        # invalidate all LevelFlags
        LevelFlag.bump_config_version()


class D810Logger(logging.Logger):
    @property
    def debug_on(self) -> LevelFlag:
        return LevelFlag(self.name, logging.DEBUG)

    @property
    def info_on(self) -> LevelFlag:
        return LevelFlag(self.name, logging.INFO)

    @property
    def warning_on(self) -> LevelFlag:
        return LevelFlag(self.name, logging.WARNING)

    @property
    def error_on(self) -> LevelFlag:
        return LevelFlag(self.name, logging.ERROR)

    @property
    def critical_on(self) -> LevelFlag:
        return LevelFlag(self.name, logging.CRITICAL)


def getLogger(name: str, default_level: int = logging.INFO) -> D810Logger:
    name = name or __name__
    # grab (or create) the underlying Logger
    base = logging.getLogger(name)
    # if it’s already the right type, just return it
    if isinstance(base, D810Logger):
        return base
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
    # replace it in the manager so future getLogger(...) calls return the subclass
    logging.Logger.manager.loggerDict[name] = new
    return new

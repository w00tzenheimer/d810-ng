import logging
import logging.config
import pathlib
import shutil
import typing

LOG_FILENAME = "d810.log"
Z3_TEST_FILENAME = "z3_check_instructions_substitution.py"

# This dictionary is a direct translation of the previous `log.ini` file.
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
            "level": "DEBUG",
            "formatter": "rawFormatter",
            "filename": None,  # Placeholder, will be set dynamically
        },
    },
    "loggers": {
        "D810": {
            "level": "DEBUG",
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
            "level": "ERROR",
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

    # The rest of your original function's logic remains the same
    z3_file_logger = logging.getLogger("D810.z3_test")
    z3_file_logger.info(
        "from z3 import BitVec, BitVecVal, UDiv, URem, LShR, UGT, UGE, ULT, ULE, prove\n\n"
    )


# Utility to dynamically query and set logger levels at runtime.
class LoggerConfigurator:
    """
    Utility to dynamically query and set logger levels at runtime.
    """

    @staticmethod
    def available_loggers(prefix: str | None = None) -> list[str]:
        """
        Return a sorted list of all logger names.
        If `prefix` is provided, filter to names equal to or starting with prefix + '.'.
        """
        mgr = logging.Logger.manager
        names = [
            name
            for name, logger in mgr.loggerDict.items()
            if isinstance(logger, logging.Logger)
        ]
        if prefix:
            names = [n for n in names if n == prefix or n.startswith(prefix + ".")]
        return sorted(names)

    @staticmethod
    def set_level(logger_name: str, level_name: str) -> None:
        """
        Change the level for `logger_name` to one of DEBUG, INFO, WARNING, ERROR, CRITICAL.
        """
        lvl = getattr(logging, level_name.upper(), None)
        if lvl is None:
            raise ValueError(f"Unknown logging level: {level_name}")
        logging.getLogger(logger_name).setLevel(lvl)

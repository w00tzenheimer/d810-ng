import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import ida_diskio


class ConfigConstants:
    """A namespace for application-wide configuration constants."""

    DEFAULT_LOG_DIR: Path = Path(ida_diskio.get_user_idadir(), "logs")
    OPTIONS_FILENAME: str = "options.json"


@dataclass
class RuleConfiguration:
    """
    Represents the configuration for a single analysis rule.

    >>> rule = RuleConfiguration(name="test_rule", is_activated=True)
    >>> rule.to_dict()
    {'name': 'test_rule', 'is_activated': True, 'config': {}}
    >>> data = {'name': 'test_rule', 'is_activated': False, 'config': {'p': 1}}
    >>> RuleConfiguration.from_dict(data).is_activated
    False
    """

    name: str | None = None
    is_activated: bool = False
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializes the rule configuration to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleConfiguration":
        """Creates a RuleConfiguration instance from a dictionary."""
        return cls(**data)


@dataclass
class ProjectConfiguration:
    """
    Holds project-specific settings, including analysis rules.
    """

    path: Path
    description: str = ""
    ins_rules: list[RuleConfiguration] = field(default_factory=list)
    blk_rules: list[RuleConfiguration] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path | str) -> "ProjectConfiguration":
        """
        Loads project configuration from a JSON file.

        Args:
            path: The path to the project configuration file.

        Returns:
            An instance of ProjectConfiguration.

        Raises:
            FileNotFoundError: If the configuration file cannot be found.
            json.JSONDecodeError: If the file is not valid JSON.
        """
        config_path = Path(path)
        logging.info("Loading project configuration from %s", config_path)
        try:
            with config_path.open("r", encoding="utf-8") as fp:
                data = json.load(fp)
        except FileNotFoundError:
            logging.error("Project configuration file not found: %s", config_path)
            raise
        except json.JSONDecodeError as e:
            logging.error("Failed to parse project config %s: %s", config_path, e)
            raise

        return cls(
            path=config_path,
            description=data.get("description", ""),
            ins_rules=[
                RuleConfiguration.from_dict(r) for r in data.get("ins_rules", [])
            ],
            blk_rules=[
                RuleConfiguration.from_dict(r) for r in data.get("blk_rules", [])
            ],
        )

    def save(self) -> None:
        """Saves the project configuration back to its file."""
        logging.info("Saving project configuration to %s", self.path)
        project_data = {
            "description": self.description,
            "ins_rules": [rule.to_dict() for rule in self.ins_rules],
            "blk_rules": [rule.to_dict() for rule in self.blk_rules],
        }

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("w", encoding="utf-8") as fp:
                json.dump(project_data, fp, indent=2)
        except IOError as e:
            logging.error(
                "Could not save project configuration to %s: %s", self.path, e
            )


class D810Configuration:
    """
    Manages application-wide configuration from a JSON file, offering
    dictionary-like access.

    >>> # Test with a temporary config file
    >>> import tempfile
    >>> temp_dir = tempfile.TemporaryDirectory()
    >>> config_path = Path(temp_dir.name) / "options.json"
    >>> config_path.write_text('{"api_key": "12345"}')
    20
    >>> config = D810Configuration(config_path)
    >>> config["api_key"]
    '12345'
    >>> str(config.log_dir) == str(ConfigConstants.DEFAULT_LOG_DIR)
    True
    >>> config["log_dir"] = "/new/logs"
    >>> str(config.log_dir)
    '/new/logs'
    >>> config.save()
    >>> loaded_data = json.loads(config_path.read_text())
    >>> loaded_data['log_dir']
    '/new/logs'
    >>> temp_dir.cleanup()
    """

    def __init__(self, config_path: Path | str | None = None):
        """
        Initializes and loads the configuration.

        Args:
            config_path: Path to the JSON config file. If None, defaults to
                         'options.json' in the script's directory.
        """
        if config_path is None:
            self.config_file = (
                Path(__file__).resolve().parent / ConfigConstants.OPTIONS_FILENAME
            )
        else:
            self.config_file = Path(config_path)

        self._options: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Loads configuration from the JSON file, handling potential errors."""
        try:
            with self.config_file.open("r", encoding="utf-8") as fp:
                self._options = json.load(fp)
        except FileNotFoundError:
            logging.warning(
                "Config file not found: %s. Using empty config.", self.config_file
            )
            self._options = {}
        except json.JSONDecodeError:
            logging.error(
                "Failed to parse config file: %s. Using empty config.", self.config_file
            )
            self._options = {}

    def save(self) -> None:
        """Saves the current configuration to the JSON file."""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with self.config_file.open("w", encoding="utf-8") as fp:
                json.dump(self._options, fp, indent=2)
            logging.info("Configuration saved to %s", self.config_file)
        except IOError as e:
            logging.error("Failed to save configuration to %s: %s", self.config_file, e)

    @property
    def log_dir(self) -> Path:
        """Returns the configured log directory, or dynamically computes default if not set."""
        path_str = self._options.get("log_dir")
        if path_str:
            return Path(path_str)
        # Dynamically get the default log directory from ida_diskio
        return Path(ida_diskio.get_user_idadir(), "logs")

    def __getitem__(self, name: str) -> Any:
        """Provides dictionary-style read access."""
        return self._options[name]

    def __setitem__(self, name: str, value: Any) -> None:
        """Provides dictionary-style write access."""
        self._options[name] = value

    def get(self, name: str, default: Any = None) -> Any:
        """Provides dictionary-style read access with a default value."""
        return self._options.get(name, default)

    def set(self, name: str, value: Any) -> None:
        """Provides dictionary-style write access."""
        self._options[name] = value

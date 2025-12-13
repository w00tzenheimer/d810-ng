import dataclasses
import json
import os
import pathlib
import sys
import typing

from .logging import getLogger

logger = getLogger(__name__)


def _get_default_ida_user_dir() -> pathlib.Path:
    """Return the default IDA user directory based on platform.

    Default locations:
    - Windows: %APPDATA%/Hex-Rays/IDA Pro
    - Linux/Mac: $HOME/.idapro
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return pathlib.Path(appdata) / "Hex-Rays" / "IDA Pro"
        # Fallback if APPDATA is not set
        return pathlib.Path.home() / "AppData" / "Roaming" / "Hex-Rays" / "IDA Pro"
    else:
        # Linux and macOS
        return pathlib.Path.home() / ".idapro"


# Default fallback for IDA user directory (used in tests or headless mode)
DEFAULT_IDA_USER_DIR = _get_default_ida_user_dir()


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigConstants:
    OPTIONS_FILENAME: typing.ClassVar[str] = "options.json"

    @staticmethod
    def default_log_dir(ida_user_dir: pathlib.Path | None = None) -> pathlib.Path:
        """Return the default log directory based on IDA user dir."""
        base = ida_user_dir if ida_user_dir is not None else DEFAULT_IDA_USER_DIR
        return base / "logs"


@dataclasses.dataclass(slots=True)
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
    config: dict[str, typing.Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, typing.Any]:
        """Serializes the rule configuration to a dictionary."""
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, typing.Any]) -> "RuleConfiguration":
        """Creates a RuleConfiguration instance from a dictionary."""
        return cls(**data)


@dataclasses.dataclass(slots=True, repr=False)
class ProjectConfiguration:
    """
    Holds project-specific settings, including analysis rules.
    """

    path: pathlib.Path
    description: str = ""
    ins_rules: list[RuleConfiguration] = dataclasses.field(default_factory=list)
    blk_rules: list[RuleConfiguration] = dataclasses.field(default_factory=list)
    additional_configuration: dict[str, typing.Any] = dataclasses.field(
        default_factory=dict
    )

    def __repr__(self) -> str:
        return f"ProjectConfiguration(path={self.path}, description={self.description}, ins_rules={len(self.ins_rules)}, blk_rules={len(self.blk_rules)}, additional_configuration={len(self.additional_configuration)})"

    @classmethod
    def from_file(cls, path: pathlib.Path | str) -> "ProjectConfiguration":
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
        config_path = pathlib.Path(path)
        logger.info("Loading project configuration from %s", config_path)
        try:
            with config_path.open("r", encoding="utf-8") as fp:
                data = json.load(fp)
        except FileNotFoundError:
            logger.error("Project configuration file not found: %s", config_path)
            raise
        except json.JSONDecodeError as e:
            logger.error("Failed to parse project config %s: %s", config_path, e)
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
        logger.info("Saving project configuration to %s", self.path)
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
            logger.error("Could not save project configuration to %s: %s", self.path, e)


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
    >>> str(config.log_dir) == str(ConfigConstants.default_log_dir())
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

    def __init__(
        self,
        config_path: pathlib.Path | str | None = None,
        *,
        ida_user_dir: pathlib.Path | str | None = None,
    ):
        """
        Initializes and loads the configuration.

        Args:
            config_path: Path to the JSON config file. If None, defaults to
                         'options.json' in the user's IDA directory.
            ida_user_dir: Path to IDA's user directory (from ida_diskio.get_user_idadir()).
                         If None, defaults to ~/.idapro.
        """
        # Store IDA user directory for config_dir and log_dir properties
        self._ida_user_dir = (
            pathlib.Path(ida_user_dir) if ida_user_dir is not None else DEFAULT_IDA_USER_DIR
        )

        if config_path is not None:
            # Caller explicitly provided a path - honor it verbatim.
            self.config_file = pathlib.Path(config_path)
            template_path: pathlib.Path | None = None
        else:
            # Default behaviour - locate user-specific options first.
            user_cfg_dir = self.config_dir
            user_cfg_dir.mkdir(parents=True, exist_ok=True)
            user_cfg_file = user_cfg_dir / ConfigConstants.OPTIONS_FILENAME

            template_path = (
                pathlib.Path(__file__).resolve().parent
                / ConfigConstants.OPTIONS_FILENAME
            )

            # Use user copy if it exists, else fall back to template for reading.
            self.config_file = user_cfg_file

        self._options: dict[str, typing.Any] = {}

        # When a template exists and the user file is absent, read from the template
        # but keep ``self.config_file`` pointing to the user path so that any save()
        # writes a copy in the writable directory.
        self._load(fallback_path=template_path)

    def _load(self, fallback_path: pathlib.Path | None = None) -> None:
        """Loads configuration from the JSON file, handling potential errors."""
        paths_to_try = [self.config_file]
        if fallback_path is not None and fallback_path not in paths_to_try:
            paths_to_try.append(fallback_path)

        for path in paths_to_try:
            try:
                with path.open("r", encoding="utf-8") as fp:
                    self._options = json.load(fp)
                logger.info("Loaded configuration from %s", path)
                break
            except FileNotFoundError:
                logger.debug("Configuration file %s not found", path)
            except json.JSONDecodeError:
                logger.error("Failed to parse config file: %s", path)

        else:
            # None of the candidate files succeeded.
            logger.warning("No valid configuration found; using defaults in memory.")
            self._options = {}

    def save(self) -> None:
        """Saves the current configuration to the JSON file."""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with self.config_file.open("w", encoding="utf-8") as fp:
                json.dump(self._options, fp, indent=2)
            logger.info("Configuration saved to %s", self.config_file)
        except IOError as e:
            logger.error("Failed to save configuration to %s: %s", self.config_file, e)

    def discover_projects(self) -> list[ProjectConfiguration]:
        """
        Discover and load all project configurations from user and plugin directories.
        """
        user_dir = self.config_dir
        # The plugin's conf directory is in d810/conf/, one level up from d810/core/
        plugin_dir = pathlib.Path(__file__).resolve().parent.parent / "conf"

        user_configs = (
            {
                p
                for p in user_dir.glob("*.json")
                if p.name != ConfigConstants.OPTIONS_FILENAME
            }
            if user_dir.exists()
            else set()
        )
        plugin_configs = {
            p
            for p in plugin_dir.glob("*.json")
            if p.name != ConfigConstants.OPTIONS_FILENAME
        }

        # User configs override plugin configs with the same name.
        # Create a dictionary of name -> path to handle overrides.
        config_paths = {p.name: p for p in plugin_configs}
        config_paths.update({p.name: p for p in user_configs})

        projects = []
        # The list of configuration names should be persisted for the UI.
        cfg_names = sorted(config_paths.keys())
        self.set("configurations", cfg_names)
        self.save()

        for name in cfg_names:
            path = config_paths[name]
            try:
                project = ProjectConfiguration.from_file(path)
                projects.append(project)
            except Exception as e:
                logger.error("Failed to load project config %s: %s", path, e)
                continue

        return projects

    def _resolve_config_path(self, cfg_name: str) -> pathlib.Path:
        """Return the full path to the configuration file.

        Precedence order:
        1. *Writable* user directory  <IDA_USER>/cfg/d810/<cfg_name>
        2. Built-in read-only templates shipped with the plugin
            (located next to this file in d810/conf/).
        """
        user_path = self.config_dir / cfg_name
        if user_path.exists():
            return user_path

        # Fallback to read-only template bundled with the plugin
        return pathlib.Path(__file__).resolve().parent / "conf" / cfg_name

    @property
    def config_dir(self) -> pathlib.Path:
        """Return the directory in the user profile that stores editable D-810 configuration files.

        The directory layout is:

        <ida_user_dir> / "cfg" / "d810"

        This location is **writable** by the user. Any project configuration JSON
        placed here will _override_ the read-only templates shipped with the
        plugin (located in the plugin package under ``d810/conf``).
        """
        return self._ida_user_dir / "cfg" / "d810"

    @property
    def log_dir(self) -> pathlib.Path:
        """Returns the configured log directory, or dynamically computes default if not set."""
        path_str = self._options.get("log_dir")
        if not path_str:
            path_str = str(ConfigConstants.default_log_dir(self._ida_user_dir))
            self._options["log_dir"] = path_str
        return pathlib.Path(path_str)

    def __getitem__(self, name: str) -> typing.Any:
        """Provides dictionary-style read access."""
        return self._options[name]

    def __setitem__(self, name: str, value: typing.Any) -> None:
        """Provides dictionary-style write access."""
        self._options[name] = value

    def get(self, name: str, default: typing.Any = None) -> typing.Any:
        """Provides dictionary-style read access with a default value."""
        return self._options.get(name, default)

    def set(self, name: str, value: typing.Any) -> None:
        """Provides dictionary-style write access."""
        self._options[name] = value

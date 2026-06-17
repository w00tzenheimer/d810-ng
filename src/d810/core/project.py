from __future__ import annotations

import dataclasses
import enum
import functools
import threading

from d810.core import typing

from .config import D810Configuration, ProjectConfiguration
from .events import EventEmitter
from .logging import getLogger

logger = getLogger(__name__)


class ProjectLifecycleEvent(enum.Enum):
    """Lifecycle events emitted around project configuration."""

    PROJECT_RELOADING = "project_reloading"


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectLifecyclePayload:
    """Payload for project lifecycle notifications."""

    reason: ProjectLifecycleEvent
    old_project_name: str | None = None
    new_project_name: str | None = None


_project_lifecycle_emitter: EventEmitter[ProjectLifecycleEvent] = EventEmitter()
_project_reload_cleanup_handlers: dict[str, typing.Callable[[], None]] = {}
_recon_fact_collector_registration_handlers: dict[str, typing.Callable[..., None]] = {}


def subscribe_project_lifecycle(
    event: ProjectLifecycleEvent,
    handler: typing.Callable[[ProjectLifecyclePayload], None],
):
    """Subscribe to project lifecycle events."""

    return _project_lifecycle_emitter.on(event, handler)


def unsubscribe_project_lifecycle(
    event: ProjectLifecycleEvent,
    handler: typing.Callable[[ProjectLifecyclePayload], None],
) -> None:
    """Remove a project lifecycle subscription."""

    _project_lifecycle_emitter.remove(event, handler)


def register_project_reload_cleanup(
    name: str,
    handler: typing.Callable[[], None],
) -> None:
    """Register a named cleanup hook for project reload.

    Registrations are keyed so repeated rule configuration replaces the same
    hook instead of accumulating duplicates.
    """

    _project_reload_cleanup_handlers[str(name)] = handler


def unregister_project_reload_cleanup(name: str) -> None:
    """Remove a named project reload cleanup hook."""

    _project_reload_cleanup_handlers.pop(str(name), None)


def register_recon_fact_collector_registration_handler(
    name: str,
    handler: typing.Callable[..., None],
) -> None:
    """Register a named project-profile fact collector callback.

    Profile modules use this callback seam to opt their own raw evidence
    collectors into a project without making :mod:`d810.manager` import profile
    code directly.  Registrations are keyed for idempotent module reloads.
    """

    _recon_fact_collector_registration_handlers[str(name)] = handler


def unregister_recon_fact_collector_registration_handler(name: str) -> None:
    """Remove a named project-profile fact collector callback."""

    _recon_fact_collector_registration_handlers.pop(str(name), None)


def emit_recon_fact_collector_registration(
    *,
    runtime: object,
    project_config: dict[str, typing.Any] | None = None,
) -> None:
    """Emit the project-profile fact collector registration callback."""

    cfg = dict(project_config or {})
    for name, handler in tuple(_recon_fact_collector_registration_handlers.items()):
        try:
            handler(runtime=runtime, project_config=cfg)
        except Exception:  # noqa: BLE001 - profile registration must not stop loading
            logger.warning(
                "recon fact collector registration failed: %s",
                name,
                exc_info=True,
            )


def _run_project_reload_cleanups() -> None:
    for name, handler in tuple(_project_reload_cleanup_handlers.items()):
        try:
            handler()
        except Exception:  # noqa: BLE001 - lifecycle cleanup must not stop loading
            logger.warning("project reload cleanup failed: %s", name, exc_info=True)


def emit_project_reloading(
    *,
    old_project_name: str | None,
    new_project_name: str | None,
) -> None:
    """Emit the pre-configuration project reload event and run cleanups."""

    payload = ProjectLifecyclePayload(
        reason=ProjectLifecycleEvent.PROJECT_RELOADING,
        old_project_name=old_project_name,
        new_project_name=new_project_name,
    )
    _run_project_reload_cleanups()
    _project_lifecycle_emitter.emit(ProjectLifecycleEvent.PROJECT_RELOADING, payload)


def clear_project_lifecycle_for_tests() -> None:
    """Clear lifecycle subscriptions and cleanup hooks for unit tests."""

    _project_reload_cleanup_handlers.clear()
    _recon_fact_collector_registration_handlers.clear()
    _project_lifecycle_emitter.clear()


@dataclasses.dataclass
class ProjectManager:
    """Manages project configurations: discovery, lookup, add, update, delete, load."""

    config: D810Configuration
    _lock: threading.Lock = dataclasses.field(
        default_factory=threading.Lock, init=False
    )
    _projects: dict[str, ProjectConfiguration] = dataclasses.field(init=False)

    def __post_init__(self):
        self.load_all()

    def __len__(self) -> int:
        with self._lock:
            return len(self._projects)

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._projects)

    def load_all(self) -> None:
        """
        Discover and register project configurations by scanning for JSON files
        in both the user's configuration directory and the plugin's built-in
        template directory. This ensures that newly added files are
        automatically detected.
        """
        projects = self.config.discover_projects()
        with self._lock:
            self._projects = {p.path.name: p for p in projects}

        if logger.debug_on:
            for k, v in self._projects.items():
                logger.debug("Project %s loaded from %s", k, v.path)

    def index(self, name: str) -> int:
        return self.project_names().index(name)

    def project_names(self) -> list[str]:
        with self._lock:
            return list(self._projects.keys())

    def projects(self) -> list[ProjectConfiguration]:
        with self._lock:
            return list(self._projects.values())

    @functools.singledispatchmethod
    def get(self, identifier: str) -> ProjectConfiguration:
        with self._lock:
            return self._projects[identifier]

    @get.register
    def _(self, identifier: int) -> ProjectConfiguration:
        with self._lock:
            lst = list(self._projects.values())
            if not 0 <= identifier < len(lst):
                available = f"0..{len(lst) - 1}" if lst else "empty"
                raise IndexError(
                    f"Unknown project index: {identifier} (available range: {available})"
                )
            return lst[identifier]

    def add(self, project: ProjectConfiguration) -> None:
        name = project.path.name
        with self._lock:
            self._projects[name] = project
        # TODO: should be part of the config responsibility
        cfg_list = self.config.get("configurations") or []
        if name not in cfg_list:
            cfg_list.append(name)
            self.config["configurations"] = cfg_list
            self.config.save()

    @functools.singledispatchmethod
    def update(self, old_name: str, new_project: ProjectConfiguration) -> None:
        with self._lock:
            if old_name not in self._projects:
                raise KeyError(f"Unknown project: {old_name}")
            if new_project.path.name != old_name:
                del self._projects[old_name]
            self._projects[new_project.path.name] = new_project

    @update.register
    def _(self, identifier: int, new_project: ProjectConfiguration) -> None:
        with self._lock:
            names = list(self._projects.keys())
        if 0 <= identifier < len(names):
            old_name = names[identifier]
        else:
            raise IndexError(f"Unknown project index: {identifier}")
        self.update(old_name, new_project)

    @functools.singledispatchmethod
    def delete(self, name: str) -> None:
        with self._lock:
            project = self._projects.pop(name, None)
            cfg_list = self.config.get("configurations") or []
            if not project:
                raise KeyError(f"Unknown project: {name}")
            if name in cfg_list:
                cfg_list.remove(name)
                self.config["configurations"] = cfg_list
                self.config.save()
        # Only allow deletion when the file lives in the user cfg directory
        user_cfg_dir = self.config.config_dir.resolve()
        path = project.path.resolve()
        if user_cfg_dir in path.parents:
            try:
                path.unlink(missing_ok=True)
            except Exception as e:
                logger.error("Failed to delete project file %s: %s", path, e)
        else:
            logger.warning("Refusing to delete read-only template: %s", path)

    @delete.register
    def _(self, project: ProjectConfiguration) -> None:
        self.delete(project.path.name)

    @delete.register
    def _(self, identifier: int) -> None:
        with self._lock:
            names = list(self._projects.keys())
        if 0 <= identifier < len(names):
            name = names[identifier]
        else:
            raise IndexError(f"Unknown project index: {identifier}")
        self.delete(name)


@dataclasses.dataclass
class ProjectContext:
    """Context for modifying project rules during a for_project block.

    This class allows dynamic rule filtering during tests or debugging:

        with state.for_project("example_libobfuscated.json") as ctx:
            ctx.remove_rule("JumpFixer")
            ctx.remove_rule(SomeRuleClass)  # Can also use class
            state.start_d810()
            # decompile...

    Changes are scoped to the context manager lifetime.
    """

    state: typing.Any  # D810State - use Any to avoid circular import
    project_index: int
    _original_ins_rules: typing.List = dataclasses.field(default_factory=list)
    _original_blk_rules: typing.List = dataclasses.field(default_factory=list)
    _original_function_priors: typing.Any = None
    _removed_rules: typing.Set[str] = dataclasses.field(default_factory=set)
    _added_rules: typing.List = dataclasses.field(default_factory=list)

    def __post_init__(self):
        # Snapshot the current rules for restoration
        self._original_ins_rules = list(self.state.current_ins_rules)
        self._original_blk_rules = list(self.state.current_blk_rules)
        self._original_function_priors = (
            self.state.manager.snapshot_function_analysis_priors()
        )

    @staticmethod
    def _rule_name(rule: str | type | typing.Any) -> str:
        if isinstance(rule, str):
            return rule.lower()
        if isinstance(rule, type):
            return rule.__name__.lower()
        name = getattr(rule, "name", None) or getattr(rule, "__name__", None)
        if name is None:
            name = rule.__class__.__name__
        return str(name).lower()

    def remove_rule(self, rule: str | type) -> ProjectContext:
        """Remove a rule from the active rules.

        Args:
            rule: Rule name (string) or rule class to remove.
                  Case-insensitive matching is used for strings.

        Returns:
            self for method chaining
        """
        name = self._rule_name(rule)

        self._removed_rules.add(name)

        # Remove from current instruction rules
        self.state.current_ins_rules = [
            r for r in self.state.current_ins_rules if r.name.lower() != name
        ]

        # Remove from current block rules
        self.state.current_blk_rules = [
            r for r in self.state.current_blk_rules if r.name.lower() != name
        ]

        logger.info("Removed rule '%s' from active rules", name)
        return self

    def add_rule(self, rule: str | type) -> ProjectContext:
        """Add a rule to the active rules.

        Args:
            rule: Rule name (string) or rule class to add.
                  The rule must exist in known_ins_rules or known_blk_rules.

        Returns:
            self for method chaining

        Raises:
            ValueError: If the rule is not found in known rules.
        """
        name = self._rule_name(rule)

        # Try to find in known instruction rules
        for known_rule in self.state.known_ins_rules:
            if known_rule.name.lower() == name:
                if known_rule not in self.state.current_ins_rules:
                    self.state.current_ins_rules.append(known_rule)
                    self._added_rules.append(known_rule)
                    logger.info("Added instruction rule '%s' to active rules", name)
                return self

        # Try to find in known block rules
        for known_rule in self.state.known_blk_rules:
            if known_rule.name.lower() == name:
                if known_rule not in self.state.current_blk_rules:
                    self.state.current_blk_rules.append(known_rule)
                    self._added_rules.append(known_rule)
                    logger.info("Added block rule '%s' to active rules", name)
                return self

        raise ValueError(f"Rule '{rule}' not found in known rules")

    def add_function_priors(
        self,
        function: str | int,
        priors: typing.Any,
    ) -> ProjectContext:
        """Add scoped analysis priors for one function.

        The concrete priors object is recon-owned.  ProjectContext only
        provides the scoped project/test harness channel and restores it on
        context exit.
        """
        self.state.manager.add_function_analysis_priors(function, priors)
        return self

    def function_analysis_priors(self, function: str | int) -> typing.Any:
        """Return the currently registered analysis priors for a function."""
        return self.state.manager.function_analysis_priors(function)

    def function_priors(self, function: str | int) -> typing.Any:
        """Short alias for tests and project-context call sites."""
        return self.function_analysis_priors(function)

    def restore(self):
        """Restore the original rules (called on context exit)."""
        self.state.current_ins_rules = self._original_ins_rules
        self.state.current_blk_rules = self._original_blk_rules
        self.state.manager.restore_function_analysis_priors(
            self._original_function_priors
        )
        if self._removed_rules:
            logger.info("Restored %d removed rules", len(self._removed_rules))
        if self._added_rules:
            logger.info("Removed %d temporarily added rules", len(self._added_rules))

    @property
    def project(self) -> ProjectConfiguration:
        """Get the current project configuration."""
        return self.state.current_project

    @property
    def active_ins_rules(self) -> typing.List:
        """Get the currently active instruction rules."""
        return self.state.current_ins_rules

    @property
    def active_blk_rules(self) -> typing.List:
        """Get the currently active block rules."""
        return self.state.current_blk_rules

    def __index__(self) -> int:
        """Support using ProjectContext as an integer for backward compatibility."""
        return self.project_index

    def __int__(self) -> int:
        """Support int() conversion for backward compatibility."""
        return self.project_index

    def __eq__(self, other) -> bool:
        """Support comparison with integers for backward compatibility."""
        if isinstance(other, int):
            return self.project_index == other
        if isinstance(other, ProjectContext):
            return self.project_index == other.project_index
        return NotImplemented

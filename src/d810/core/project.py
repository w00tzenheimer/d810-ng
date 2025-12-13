from __future__ import annotations

import dataclasses
import functools
import threading
import typing
from typing import TYPE_CHECKING

from .config import D810Configuration, ProjectConfiguration
from .logging import getLogger

if TYPE_CHECKING:
    pass  # For future type hints

logger = getLogger(__name__)


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
            if logger.debug_on and 0 > identifier >= len(lst):
                logger.error("Unknown project index: %s", identifier)
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
            ctx.remove_rule("FixPredecessorOfConditionalJumpBlock")
            ctx.remove_rule(SomeRuleClass)  # Can also use class
            state.start_d810()
            # decompile...

    Changes are scoped to the context manager lifetime.
    """

    state: typing.Any  # D810State - use Any to avoid circular import
    project_index: int
    _original_ins_rules: typing.List = dataclasses.field(default_factory=list)
    _original_blk_rules: typing.List = dataclasses.field(default_factory=list)
    _removed_rules: typing.Set[str] = dataclasses.field(default_factory=set)
    _added_rules: typing.List = dataclasses.field(default_factory=list)

    def __post_init__(self):
        # Snapshot the current rules for restoration
        self._original_ins_rules = list(self.state.current_ins_rules)
        self._original_blk_rules = list(self.state.current_blk_rules)

    def remove_rule(self, rule: str | type) -> ProjectContext:
        """Remove a rule from the active rules.

        Args:
            rule: Rule name (string) or rule class to remove.
                  Case-insensitive matching is used for strings.

        Returns:
            self for method chaining
        """
        if isinstance(rule, str):
            name = rule.lower()
        else:
            name = rule.__name__.lower()

        self._removed_rules.add(name)

        # Remove from current instruction rules
        self.state.current_ins_rules = [
            r for r in self.state.current_ins_rules
            if r.name.lower() != name
        ]

        # Remove from current block rules
        self.state.current_blk_rules = [
            r for r in self.state.current_blk_rules
            if r.name.lower() != name
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
        if isinstance(rule, str):
            name = rule.lower()
        else:
            name = rule.__name__.lower()

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

    def restore(self):
        """Restore the original rules (called on context exit)."""
        self.state.current_ins_rules = self._original_ins_rules
        self.state.current_blk_rules = self._original_blk_rules
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

import dataclasses
import functools
import threading

from d810.conf import D810Configuration, ProjectConfiguration
from d810.conf.loggers import getLogger

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

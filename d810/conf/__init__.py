import json
from pathlib import Path

import ida_diskio

DEFAULT_LOG_DIR = Path(ida_diskio.get_user_idadir(), "logs")


class D810Configuration(object):
    def __init__(self):
        self.config_dir = Path(__file__).resolve().parent
        self.config_file = self.config_dir / "options.json"
        with self.config_file.open("r") as fp:
            self._options = json.load(fp)

    def get(self, name):
        if name == "log_dir" and not self._options.get(name):
            return str(DEFAULT_LOG_DIR)
        return self._options[name]

    def set(self, name, value):
        self._options[name] = value

    def save(self):
        with self.config_file.open("w+") as fp:
            json.dump(self._options, fp, indent=2)


class RuleConfiguration(object):
    def __init__(self, name=None, is_activated=False, config=None):
        self.name = name
        self.is_activated = is_activated
        self.config = config if config is not None else {}

    def to_dict(self):
        return {
            "name": self.name,
            "is_activated": self.is_activated,
            "config": self.config,
        }

    @staticmethod
    def from_dict(kwargs):
        return RuleConfiguration(**kwargs)


class ProjectConfiguration(object):
    def __init__(
        self, path, description=None, ins_rules=None, blk_rules=None, conf_dir=None
    ):
        self.path = Path(path)
        self.description = description
        self.conf_dir = Path(conf_dir) if conf_dir is not None else None
        self.ins_rules = [] if ins_rules is None else ins_rules
        self.blk_rules = [] if blk_rules is None else blk_rules
        self.additional_configuration = {}

    def load(self):
        if self.path.exists():
            with self.path.open("r") as fp:
                project_conf = json.load(fp)
        else:
            if self.conf_dir is not None:
                self.path = self.conf_dir / self.path
                with self.path.open("r") as fp:
                    project_conf = json.load(fp)

        self.description = project_conf["description"]
        self.ins_rules = [
            RuleConfiguration.from_dict(x) for x in project_conf["ins_rules"]
        ]
        self.blk_rules = [
            RuleConfiguration.from_dict(x) for x in project_conf["blk_rules"]
        ]

    def save(self):
        project_conf = {
            "description": self.description,
            "ins_rules": [x.to_dict() for x in self.ins_rules],
            "blk_rules": [x.to_dict() for x in self.blk_rules],
        }
        with open(self.path, "w") as fp:
            json.dump(project_conf, fp, indent=2)

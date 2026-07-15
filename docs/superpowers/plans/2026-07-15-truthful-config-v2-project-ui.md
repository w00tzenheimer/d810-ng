# Truthful Config-v2 Project UI - Slice 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing D810 configuration form report the actual source and runtime project, show effective config-v2 passes and runtime-expanded rules, preserve complete configuration documents during save/duplicate, and refuse flat edits that cannot be proven lossless.

**Architecture:** A core persistence service owns complete-document JSON mutation and atomic writes. An IDA-independent manager module projects the selected source project plus effective runtime activation into an immutable snapshot and owns the guarded save/clone command facade. A pure `project_config_logic.py` module turns that snapshot into presentation and edit/save decisions. `ida_ui.py` remains thin Qt glue, calls manager commands rather than persistence, and never derives config-v2 behavior from the legacy rule tree.

**Tech Stack:** Python 3.13, dataclasses, pathlib/tempfile/JSON, D810 config-v2 routing and hook bridge, IDAPython with the existing Qt shim, pytest, ast-grep, import-linter, graphify, and `tk`.

## Global Constraints

- Implement ticket `d81-kcin`, child of approved workbench ticket `d81-38ha`.
- Invoke `superpowers:using-git-worktrees` before implementation. The current checkout contains unrelated user WIP; implement on an isolated `diff/` worktree created from the commit containing this plan.
- Preserve bundled-project provenance rules. A user config with a bundled basename must not gain bundled routing trust.
- A routed source and its effective runtime are distinct identities. Never collapse them into one label or one mutable `ProjectConfiguration`.
- The flat rule tree edits legacy projects only. Routed defaults and directly selected config-v2 projects are read-only in that editor.
- Config-v2 Duplicate copies the complete effective runtime document. It must not serialize runtime-expanded hook rules into legacy `ins_rules` or `blk_rules`.
- Complete-document preservation is semantic JSON preservation: every unedited key/value survives, even if formatting or key order changes.
- Project writes use a sibling temporary file, validate by reloading, and replace the destination atomically. A failed write leaves any prior destination unchanged.
- UI policy lives in pure `*_logic.py`; Qt callbacks only collect widget values, call the pure policy and manager command APIs, and render returned values.
- `d810.ui` must not import the pass registry, core persistence implementation, or derive `pipeline_v2` behavior. The manager snapshot and command facade are the UI's source of truth.
- Add no ast-grep or import-linter ignores. Read `.importlinter` and relevant `rules/` YAML before addressing any boundary failure.
- Do not touch the Recipe Composer, function overrides, Diagnostics Explorer/Cleaner, or advanced v2 editing in this slice.
- No deobfuscation transform changes are authorized. The native-decompile oracle is therefore not a Slice 0 behavior gate; existing pipeline tests must remain green and the OLLVM runtime activation witness is the relevant executable oracle.
- Run the full unit suite once for the isolated-worktree baseline and once at the end. Use focused tests between those runs.

---

### Task 0: Establish the isolated baseline

**Files:**

- Read: `.claude/rules/CORE_INSTRUCTIONS.md`
- Read: `.importlinter`
- Read: `rules/no-live-ida-in-portable-core.yml`
- Read: `rules/no-concrete-isinstance.yml`
- Read: `rules/use-qt-dialog-exec-underscore.yml`
- Track: `.tickets/d81-kcin.md`

**Interfaces:**

- Consumes: the commit containing this plan and the existing dirty-checkout inventory.
- Produces: an isolated implementation worktree with a recorded green or explicitly pre-existing-red unit baseline.

- [ ] **Step 1: Create the implementation worktree**

Invoke `superpowers:using-git-worktrees` and create a branch with the `diff/` prefix. Do not copy, stash, stage, or reset the unrelated changes from the original checkout.

- [ ] **Step 2: Confirm ticket and worktree scope**

Run:

```bash
tk show d81-kcin
git status --short
git branch --show-current
```

Expected: `d81-kcin` is `in_progress`; the implementation worktree does not contain the original checkout's unrelated Rhad/PREOPT modifications.

- [ ] **Step 3: Run the one-time unit baseline**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest tests/unit/ -q --tb=short
```

Expected: pass. If the baseline is red, record exact failing node IDs and output in `tk add-note d81-kcin`; do not conflate those failures with Slice 0.

---

### Task 1: Add complete-document, atomic project persistence

**Files:**

- Create: `src/d810/core/project_config_persistence.py`
- Create: `tests/unit/core/test_project_config_persistence.py`
- Reference: `src/d810/core/config.py:46-145`

**Interfaces:**

- `clone_project_configuration(*, source: ProjectConfiguration, destination: Path, description: str) -> ProjectConfiguration`
- `save_legacy_project_configuration(*, source: ProjectConfiguration | None, destination: Path, description: str, ins_rules: Sequence[RuleConfiguration], blk_rules: Sequence[RuleConfiguration]) -> ProjectConfiguration`
- `ProjectConfigurationWriteError`, raised after temporary-file cleanup while preserving the prior destination.

The module imports no IDA, Qt, manager, pass, or UI code.

- [ ] **Step 1: Write the failing persistence tests**

Add this fixture and these tests:

```python
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    clone_project_configuration,
    save_legacy_project_configuration,
)


def _write_source(path: Path) -> ProjectConfiguration:
    path.write_text(
        json.dumps(
            {
                "description": "source",
                "ins_rules": [],
                "blk_rules": [],
                "future_top_level": {"retain": [1, 2, 3]},
                "additional_configuration": {
                    "pipeline_v2_mode": "config-v2",
                    "recon_fact_profile_modules": ["example.profile"],
                    "pipeline_v2": [
                        {
                            "pass": "recover_dispatcher",
                            "migration": {"source_section": "blk_rules"},
                            "options": {"nested": {"threshold": 7}},
                        }
                    ],
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return ProjectConfiguration.from_file(path)


def test_clone_changes_only_path_and_description_and_preserves_nested_v2_payload(
    tmp_path: Path,
) -> None:
    source = _write_source(tmp_path / "source.json")
    destination = tmp_path / "copy.json"

    duplicate = clone_project_configuration(
        source=source,
        destination=destination,
        description="copy",
    )

    expected = json.loads(source.path.read_text(encoding="utf-8"))
    expected["description"] = "copy"
    assert json.loads(destination.read_text(encoding="utf-8")) == expected
    assert duplicate.path == destination
    assert duplicate.additional_configuration == source.additional_configuration


def test_legacy_save_preserves_unrepresented_top_level_fields(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json")
    destination = tmp_path / "legacy-copy.json"
    ins_rule = RuleConfiguration(name="InstructionRule", is_activated=True)
    blk_rule = RuleConfiguration(name="BlockRule", is_activated=True)

    save_legacy_project_configuration(
        source=source,
        destination=destination,
        description="legacy copy",
        ins_rules=(ins_rule,),
        blk_rules=(blk_rule,),
    )

    actual = json.loads(destination.read_text(encoding="utf-8"))
    assert actual["description"] == "legacy copy"
    assert actual["ins_rules"] == [ins_rule.to_dict()]
    assert actual["blk_rules"] == [blk_rule.to_dict()]
    assert actual["future_top_level"] == {"retain": [1, 2, 3]}
    assert actual["additional_configuration"] == source.additional_configuration


def test_new_legacy_save_has_the_canonical_four_top_level_fields(tmp_path: Path) -> None:
    destination = tmp_path / "new.json"

    save_legacy_project_configuration(
        source=None,
        destination=destination,
        description="new",
        ins_rules=(),
        blk_rules=(),
    )

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "description": "new",
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {},
    }


def test_atomic_reload_failure_leaves_existing_destination_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source.json")
    destination = tmp_path / "destination.json"
    destination.write_text('{"sentinel": "old"}', encoding="utf-8")

    def reject_temporary(path: Path | str) -> ProjectConfiguration:
        raise ValueError(f"rejected {path}")

    monkeypatch.setattr(ProjectConfiguration, "from_file", reject_temporary)

    with pytest.raises(ProjectConfigurationWriteError, match="destination.json"):
        clone_project_configuration(
            source=source,
            destination=destination,
            description="copy",
        )

    assert destination.read_text(encoding="utf-8") == '{"sentinel": "old"}'


def test_atomic_replace_failure_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source.json")
    destination = tmp_path / "destination.json"

    def reject_replace(source_path: Path | str, destination_path: Path | str) -> None:
        raise OSError(f"cannot replace {source_path} -> {destination_path}")

    monkeypatch.setattr(os, "replace", reject_replace)

    with pytest.raises(ProjectConfigurationWriteError, match="destination.json"):
        clone_project_configuration(
            source=source,
            destination=destination,
            description="copy",
        )

    assert not destination.exists()
    assert list(tmp_path.glob(".destination.json.*.tmp")) == []
```

Use a source document containing a sentinel unknown top-level field plus nested `additional_configuration.pipeline_v2` migration/options data. For the clone, compare parsed JSON after changing only `description`. For the legacy update, assert `description`, `ins_rules`, and `blk_rules` change while the sentinel and complete `additional_configuration` remain equal.

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/core/test_project_config_persistence.py
```

Expected: collection fails because `d810.core.project_config_persistence` does not exist.

- [ ] **Step 3: Implement the minimal persistence service**

Create `src/d810/core/project_config_persistence.py` with this complete implementation:

```python
from __future__ import annotations

import json
import os
import pathlib
import tempfile
from collections.abc import Sequence

from d810.core import typing
from d810.core.config import ProjectConfiguration, RuleConfiguration


class ProjectConfigurationWriteError(RuntimeError):
    """A complete project document could not be validated and committed."""


def _read_complete_document(path: pathlib.Path) -> dict[str, typing.Any]:
    try:
        with path.open("r", encoding="utf-8") as fp:
            return typing.cast(dict[str, typing.Any], json.load(fp))
    except Exception as exc:
        raise ProjectConfigurationWriteError(
            f"Could not read complete project configuration {path}"
        ) from exc


def _write_document_atomically(
    destination: pathlib.Path,
    document: dict[str, typing.Any],
) -> ProjectConfiguration:
    destination = pathlib.Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: pathlib.Path | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temp_path = pathlib.Path(temp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(document, fp, indent=2)
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
        validated = ProjectConfiguration.from_file(temp_path)
        os.replace(temp_path, destination)
        temp_path = None
        validated.path = destination
        return validated
    except Exception as exc:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise ProjectConfigurationWriteError(
            f"Could not atomically write project configuration {destination}"
        ) from exc


def clone_project_configuration(
    *,
    source: ProjectConfiguration,
    destination: pathlib.Path,
    description: str,
) -> ProjectConfiguration:
    document = _read_complete_document(source.path)
    document["description"] = description
    return _write_document_atomically(destination, document)


def save_legacy_project_configuration(
    *,
    source: ProjectConfiguration | None,
    destination: pathlib.Path,
    description: str,
    ins_rules: Sequence[RuleConfiguration],
    blk_rules: Sequence[RuleConfiguration],
) -> ProjectConfiguration:
    document = _read_complete_document(source.path) if source is not None else {}
    document["description"] = description
    document["ins_rules"] = [rule.to_dict() for rule in ins_rules]
    document["blk_rules"] = [rule.to_dict() for rule in blk_rules]
    document.setdefault("additional_configuration", {})
    return _write_document_atomically(destination, document)
```

Do not call `ProjectConfiguration.save()` from this service: that method reconstructs the document from represented fields and is the behavior this slice is replacing in the UI path.

- [ ] **Step 4: Verify GREEN and the existing config tests**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/core/test_project_config_persistence.py \
  tests/unit/core/test_config.py
```

Expected: all tests pass; no sibling `*.tmp` file remains after either success or failure.

- [ ] **Step 5: Commit the persistence boundary**

```bash
git add src/d810/core/project_config_persistence.py tests/unit/core/test_project_config_persistence.py
git commit -m "feat(config): add lossless atomic project persistence"
```

---

### Task 2: Expose immutable source/runtime truth from the manager layer

**Files:**

- Create: `src/d810/manager/project_runtime.py`
- Create: `tests/unit/manager/test_project_runtime.py`
- Modify: `src/d810/manager/state.py:54-88`
- Modify: `src/d810/manager/state.py:109-151`
- Modify: `src/d810/manager/__init__.py:1-27`
- Reference: `src/d810/core/config_v2_defaults.py:19-43,315-370`
- Reference: `src/d810/passes/pipeline_v2_hook_bridge.py:34-42,145-196`

**Interfaces:**

- `ProjectConfigMode`: `LEGACY` or `CONFIG_V2`.
- `RuleProjectionKind`: `SOURCE_POLICY` or `RUNTIME_EXPANSION`.
- `ProjectIdentitySnapshot`: immutable basename, absolute path, and description.
- `ProjectRuntimeSnapshot`: immutable source/runtime identities, mode, routed flag, hook mode, effective pass IDs, effective instruction-rule names, effective block-rule names, and projection kind.
- `build_project_runtime_snapshot(*, source_project: ProjectConfiguration, runtime_project: ProjectConfiguration, default_selection: ConfigV2DefaultSelection | None, hook_activation: PipelineV2HookActivation, hook_mode: str | None) -> ProjectRuntimeSnapshot`.
- `ProjectConfigurationEditError`, raised by the manager command facade when a caller requests a legacy write for config-v2 state or requests a runtime clone without a runtime project.
- `clone_runtime_project(*, runtime_project: ProjectConfiguration | None, destination: Path, description: str) -> ProjectConfiguration`.
- `save_legacy_project(*, snapshot: ProjectRuntimeSnapshot | None, source: ProjectConfiguration | None, destination: Path, description: str, ins_rules: Sequence[RuleConfiguration], blk_rules: Sequence[RuleConfiguration]) -> ProjectConfiguration`.
- `D810State.get_project_runtime_snapshot() -> ProjectRuntimeSnapshot`.
- `D810State.clone_current_runtime_project(destination: Path, description: str) -> ProjectConfiguration`.
- `D810State.save_legacy_project(snapshot: ProjectRuntimeSnapshot | None, source: ProjectConfiguration | None, destination: Path, description: str, ins_rules: Sequence[RuleConfiguration], blk_rules: Sequence[RuleConfiguration]) -> ProjectConfiguration`.

- [ ] **Step 1: Write the failing snapshot tests**

Add this complete test module:

```python
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.config_v2_defaults import select_config_v2_default_project
from d810.manager.project_runtime import (
    ProjectConfigurationEditError,
    ProjectConfigMode,
    RuleProjectionKind,
    build_project_runtime_snapshot,
    clone_runtime_project,
    save_legacy_project,
)
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


CONF_DIR = Path("src/d810/conf")


def test_legacy_snapshot_reports_source_policy_and_only_active_rules(
    tmp_path: Path,
) -> None:
    project = ProjectConfiguration(
        path=tmp_path / "legacy.json",
        description="legacy",
        ins_rules=[
            RuleConfiguration(name="EnabledInstruction", is_activated=True),
            RuleConfiguration(name="DisabledInstruction", is_activated=False),
        ],
        blk_rules=[RuleConfiguration(name="EnabledBlock", is_activated=True)],
    )
    activation = pipeline_v2_hook_activation(project)

    snapshot = build_project_runtime_snapshot(
        source_project=project,
        runtime_project=project,
        default_selection=None,
        hook_activation=activation,
        hook_mode=None,
    )

    assert snapshot.mode is ProjectConfigMode.LEGACY
    assert snapshot.rule_projection is RuleProjectionKind.SOURCE_POLICY
    assert snapshot.routed is False
    assert snapshot.effective_pass_ids == ()
    assert snapshot.effective_instruction_rule_names == ("EnabledInstruction",)
    assert snapshot.effective_block_rule_names == ("EnabledBlock",)


def test_routed_config_v2_snapshot_reports_distinct_source_and_runtime() -> None:
    source = ProjectConfiguration.from_file(CONF_DIR / "default_instruction_only.json")
    selection = select_config_v2_default_project(source)
    assert selection is not None
    activation = pipeline_v2_hook_activation(selection.runtime_project)

    snapshot = build_project_runtime_snapshot(
        source_project=source,
        runtime_project=selection.runtime_project,
        default_selection=selection,
        hook_activation=activation,
        hook_mode="config-v2",
    )

    assert snapshot.source.basename == "default_instruction_only.json"
    assert snapshot.runtime.basename == "default_instruction_only_config_v2_canary.json"
    assert snapshot.source.path != snapshot.runtime.path
    assert snapshot.mode is ProjectConfigMode.CONFIG_V2
    assert snapshot.routed is True
    assert snapshot.hook_mode == "config-v2"
    assert snapshot.effective_pass_ids == (
        "mba-simplify",
        "global-constant-inliner",
        "jump-fixer",
    )
    assert len(snapshot.effective_instruction_rule_names) == 179
    assert len(snapshot.effective_block_rule_names) == 2


def test_direct_canary_snapshot_is_config_v2_without_routing() -> None:
    canary = ProjectConfiguration.from_file(
        CONF_DIR / "default_instruction_only_config_v2_canary.json"
    )
    selection = select_config_v2_default_project(canary)
    assert selection is not None
    activation = pipeline_v2_hook_activation(selection.runtime_project)

    snapshot = build_project_runtime_snapshot(
        source_project=canary,
        runtime_project=selection.runtime_project,
        default_selection=selection,
        hook_activation=activation,
        hook_mode="config-v2",
    )

    assert snapshot.source == snapshot.runtime
    assert snapshot.mode is ProjectConfigMode.CONFIG_V2
    assert snapshot.routed is False
    assert snapshot.rule_projection is RuleProjectionKind.RUNTIME_EXPANSION
    assert len(snapshot.effective_instruction_rule_names) == 179
    assert len(snapshot.effective_block_rule_names) == 2


def test_snapshot_is_immutable(tmp_path: Path) -> None:
    project = ProjectConfiguration(path=tmp_path / "legacy.json")
    snapshot = build_project_runtime_snapshot(
        source_project=project,
        runtime_project=project,
        default_selection=None,
        hook_activation=pipeline_v2_hook_activation(project),
        hook_mode=None,
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.routed = True


def test_manager_refuses_legacy_write_for_config_v2_snapshot(tmp_path: Path) -> None:
    canary = ProjectConfiguration.from_file(
        CONF_DIR / "default_instruction_only_config_v2_canary.json"
    )
    selection = select_config_v2_default_project(canary)
    assert selection is not None
    snapshot = build_project_runtime_snapshot(
        source_project=canary,
        runtime_project=selection.runtime_project,
        default_selection=selection,
        hook_activation=pipeline_v2_hook_activation(selection.runtime_project),
        hook_mode="config-v2",
    )

    with pytest.raises(ProjectConfigurationEditError, match="legacy rule editor"):
        save_legacy_project(
            snapshot=snapshot,
            source=canary,
            destination=tmp_path / "forbidden.json",
            description="forbidden",
            ins_rules=(),
            blk_rules=(),
        )

    assert not (tmp_path / "forbidden.json").exists()


def test_manager_requires_runtime_project_for_clone(tmp_path: Path) -> None:
    with pytest.raises(ProjectConfigurationEditError, match="No effective runtime"):
        clone_runtime_project(
            runtime_project=None,
            destination=tmp_path / "missing.json",
            description="missing",
        )
```

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/manager/test_project_runtime.py
```

Expected: collection fails because `d810.manager.project_runtime` does not exist.

- [ ] **Step 3: Implement the IDA-independent snapshot model**

Create `src/d810/manager/project_runtime.py` with this complete implementation:

```python
from __future__ import annotations

import dataclasses
import enum
import pathlib
from collections.abc import Sequence

from d810.core.config import ProjectConfiguration, RuleConfiguration
from d810.core.config_v2_defaults import ConfigV2DefaultSelection
from d810.core.project_config_persistence import (
    ProjectConfigurationWriteError,
    clone_project_configuration,
    save_legacy_project_configuration,
)
from d810.passes.pipeline_v2_hook_bridge import PipelineV2HookActivation


class ProjectConfigMode(enum.Enum):
    LEGACY = "legacy"
    CONFIG_V2 = "config-v2"


class RuleProjectionKind(enum.Enum):
    SOURCE_POLICY = "source-policy"
    RUNTIME_EXPANSION = "runtime-expansion"


class ProjectConfigurationEditError(RuntimeError):
    """A project edit command is incompatible with the active runtime mode."""


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectIdentitySnapshot:
    basename: str
    path: pathlib.Path
    description: str


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectRuntimeSnapshot:
    source: ProjectIdentitySnapshot
    runtime: ProjectIdentitySnapshot
    mode: ProjectConfigMode
    routed: bool
    hook_mode: str | None
    effective_pass_ids: tuple[str, ...]
    effective_instruction_rule_names: tuple[str, ...]
    effective_block_rule_names: tuple[str, ...]
    rule_projection: RuleProjectionKind


def _identity(project: ProjectConfiguration) -> ProjectIdentitySnapshot:
    return ProjectIdentitySnapshot(
        basename=project.path.name,
        path=project.path.resolve(),
        description=project.description,
    )


def _active_rule_names(
    rules: list[RuleConfiguration] | tuple[RuleConfiguration, ...],
) -> tuple[str, ...]:
    return tuple(
        str(rule.name)
        for rule in rules
        if rule.is_activated and rule.name
    )


def build_project_runtime_snapshot(
    *,
    source_project: ProjectConfiguration,
    runtime_project: ProjectConfiguration,
    default_selection: ConfigV2DefaultSelection | None,
    hook_activation: PipelineV2HookActivation,
    hook_mode: str | None,
) -> ProjectRuntimeSnapshot:
    if hook_activation.enabled:
        mode = ProjectConfigMode.CONFIG_V2
        projection = RuleProjectionKind.RUNTIME_EXPANSION
        pass_ids = hook_activation.configured_pass_ids
        instruction_rule_names = _active_rule_names(
            hook_activation.instruction_rules
        )
        block_rule_names = _active_rule_names(hook_activation.block_rules)
    else:
        mode = ProjectConfigMode.LEGACY
        projection = RuleProjectionKind.SOURCE_POLICY
        pass_ids = ()
        instruction_rule_names = _active_rule_names(runtime_project.ins_rules)
        block_rule_names = _active_rule_names(runtime_project.blk_rules)

    return ProjectRuntimeSnapshot(
        source=_identity(source_project),
        runtime=_identity(runtime_project),
        mode=mode,
        routed=bool(default_selection and default_selection.routed),
        hook_mode=hook_mode,
        effective_pass_ids=pass_ids,
        effective_instruction_rule_names=instruction_rule_names,
        effective_block_rule_names=block_rule_names,
        rule_projection=projection,
    )


def clone_runtime_project(
    *,
    runtime_project: ProjectConfiguration | None,
    destination: pathlib.Path,
    description: str,
) -> ProjectConfiguration:
    if runtime_project is None:
        raise ProjectConfigurationEditError(
            "No effective runtime project is available to duplicate"
        )
    try:
        return clone_project_configuration(
            source=runtime_project,
            destination=destination,
            description=description,
        )
    except ProjectConfigurationWriteError as exc:
        raise ProjectConfigurationEditError(str(exc)) from exc


def save_legacy_project(
    *,
    snapshot: ProjectRuntimeSnapshot | None,
    source: ProjectConfiguration | None,
    destination: pathlib.Path,
    description: str,
    ins_rules: Sequence[RuleConfiguration],
    blk_rules: Sequence[RuleConfiguration],
) -> ProjectConfiguration:
    if snapshot is not None and snapshot.mode is ProjectConfigMode.CONFIG_V2:
        raise ProjectConfigurationEditError(
            "The legacy rule editor cannot save a config-v2 project"
        )
    try:
        return save_legacy_project_configuration(
            source=source,
            destination=destination,
            description=description,
            ins_rules=ins_rules,
            blk_rules=blk_rules,
        )
    except ProjectConfigurationWriteError as exc:
        raise ProjectConfigurationEditError(str(exc)) from exc
```

This returns only immutable identities, strings, and tuples. It does not return a mutable `ProjectConfiguration` or `RuleConfiguration`.

- [ ] **Step 4: Wire one snapshot into `D810State.load_project()`**

Import `ProjectRuntimeSnapshot`, `build_project_runtime_snapshot`, `clone_runtime_project` as `clone_runtime_project_command`, and `save_legacy_project` as `save_legacy_project_command` into `state.py`. Add this reset assignment next to the existing config-v2 fields:

```python
self.current_project_runtime_snapshot: ProjectRuntimeSnapshot | None = None
```

After the existing activation `if/else` selects `project_ins_rules` and `project_blk_rules`, add:

```python
self.current_project_runtime_snapshot = build_project_runtime_snapshot(
    source_project=self.current_project,
    runtime_project=runtime_project,
    default_selection=default_selection,
    hook_activation=hook_activation,
    hook_mode=self.last_pipeline_v2_hook_mode,
)
```

Add the accessor immediately before `_register_backend_analysis_providers()`:

```python
def get_project_runtime_snapshot(self) -> ProjectRuntimeSnapshot:
    snapshot = self.current_project_runtime_snapshot
    if snapshot is None:
        raise RuntimeError("No project runtime snapshot is available")
    return snapshot
```

Add these manager command facades immediately after the accessor:

```python
def clone_current_runtime_project(
    self,
    destination: pathlib.Path,
    description: str,
) -> ProjectConfiguration:
    return clone_runtime_project_command(
        runtime_project=self.current_runtime_project,
        destination=destination,
        description=description,
    )

def save_legacy_project(
    self,
    *,
    snapshot: ProjectRuntimeSnapshot | None,
    source: ProjectConfiguration | None,
    destination: pathlib.Path,
    description: str,
    ins_rules: typing.Sequence[RuleConfiguration],
    blk_rules: typing.Sequence[RuleConfiguration],
) -> ProjectConfiguration:
    return save_legacy_project_command(
        snapshot=snapshot,
        source=source,
        destination=destination,
        description=description,
        ins_rules=ins_rules,
        blk_rules=blk_rules,
    )
```

Add `RuleConfiguration` to the existing `d810.core.config` import in `state.py`. The command functions raise `ProjectConfigurationEditError`, which the manager package exports lazily for the UI adapter to catch.

Keep `current_project`, `current_runtime_project`, `last_config_v2_default_selection`, `last_pipeline_v2_hook_mode`, and `last_pipeline_v2_hook_pass_ids` intact for compatibility. The snapshot consolidates them; it does not replace their current callers in this slice.

Add `ProjectConfigurationEditError`, `ProjectConfigMode`, `ProjectIdentitySnapshot`, `ProjectRuntimeSnapshot`, and `RuleProjectionKind` to `src/d810/manager/__init__.py::__all__`, then add this lazy branch before the existing `D810State` branch:

```python
if name in {
    "ProjectConfigurationEditError",
    "ProjectConfigMode",
    "ProjectIdentitySnapshot",
    "ProjectRuntimeSnapshot",
    "RuleProjectionKind",
}:
    from d810.manager import project_runtime

    return getattr(project_runtime, name)
```

This keeps unit imports from forcing `D810State` or live IDA modules.

- [ ] **Step 5: Verify GREEN and routing compatibility**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/manager/test_project_runtime.py \
  tests/unit/core/test_config_v2_defaults.py \
  tests/unit/passes/test_pipeline_v2_hook_bridge.py
```

Expected: all tests pass, including user-override provenance tests.

- [ ] **Step 6: Commit the manager snapshot**

```bash
git add src/d810/manager/project_runtime.py src/d810/manager/state.py src/d810/manager/__init__.py tests/unit/manager/test_project_runtime.py
git commit -m "feat(manager): expose runtime project snapshots"
```

---

### Task 3: Extract pure configuration presentation and edit policy

**Files:**

- Create: `src/d810/ui/project_config_logic.py`
- Create: `tests/unit/ui/test_project_config_logic.py`
- Reference: `src/d810/ui/actions_logic.py:1-37`
- Reference: `tests/unit/ui/test_actions_logic.py:1-74`

**Interfaces:**

- `ConfigEditMode`: `NEW`, `DUPLICATE`, or `EDIT`.
- `ConfigSaveStrategy`: `CREATE_LEGACY`, `SAVE_LEGACY_COPY`, `CLONE_RUNTIME_V2`, or `REFUSE`.
- `ProjectConfigView`: immutable text/tooltips, effective rule names, rule title, pass summary, and edit-button state.
- `ConfigEditPolicy`: immutable allowed flag, rules-editable flag, save strategy, and refusal/explanation text.
- `build_project_config_view(snapshot: ProjectRuntimeSnapshot) -> ProjectConfigView`.
- `select_config_edit_policy(mode: ConfigEditMode, snapshot: ProjectRuntimeSnapshot | None) -> ConfigEditPolicy`.

- [ ] **Step 1: Write the failing projection and action-decision tests**

Add this complete test module:

```python
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import d810.ui.project_config_logic as project_config_logic
from d810.manager.project_runtime import (
    ProjectConfigMode,
    ProjectIdentitySnapshot,
    ProjectRuntimeSnapshot,
    RuleProjectionKind,
)
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigSaveStrategy,
    build_project_config_view,
    select_config_edit_policy,
)


def _snapshot(
    *,
    mode: ProjectConfigMode,
    routed: bool,
) -> ProjectRuntimeSnapshot:
    source = ProjectIdentitySnapshot(
        basename="source.json",
        path=Path("/configs/source.json"),
        description="source",
    )
    runtime = ProjectIdentitySnapshot(
        basename="runtime.json" if routed else "source.json",
        path=Path("/configs/runtime.json" if routed else "/configs/source.json"),
        description="runtime" if routed else "source",
    )
    if mode is ProjectConfigMode.CONFIG_V2:
        return ProjectRuntimeSnapshot(
            source=source,
            runtime=runtime,
            mode=mode,
            routed=routed,
            hook_mode="config-v2",
            effective_pass_ids=("pass-a", "pass-b"),
            effective_instruction_rule_names=("InsA", "InsB"),
            effective_block_rule_names=("BlkA",),
            rule_projection=RuleProjectionKind.RUNTIME_EXPANSION,
        )
    return ProjectRuntimeSnapshot(
        source=source,
        runtime=runtime,
        mode=mode,
        routed=False,
        hook_mode=None,
        effective_pass_ids=(),
        effective_instruction_rule_names=("LegacyIns",),
        effective_block_rule_names=("LegacyBlk",),
        rule_projection=RuleProjectionKind.SOURCE_POLICY,
    )


def test_routed_v2_view_shows_both_identities_runtime_rules_and_passes() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True)
    )

    assert view.mode_text == "Config v2 (routed)"
    assert view.source_text == "source.json"
    assert view.runtime_text == "runtime.json"
    assert view.source_tooltip == "/configs/source.json"
    assert view.runtime_tooltip == "/configs/runtime.json"
    assert view.effective_passes_text == "2 passes: pass-a, pass-b"
    assert view.rules_title == "Rules (runtime expansion: 2 instruction, 1 block)"
    assert view.enabled_rule_names == frozenset({"InsA", "InsB", "BlkA"})
    assert view.edit_enabled is False


def test_direct_v2_view_marks_config_v2_without_routed_suffix() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=False)
    )

    assert view.mode_text == "Config v2"
    assert view.source_text == view.runtime_text == "source.json"
    assert view.source_tooltip == view.runtime_tooltip == "/configs/source.json"


def test_legacy_view_marks_source_policy_and_no_effective_pass_manifest() -> None:
    view = build_project_config_view(
        _snapshot(mode=ProjectConfigMode.LEGACY, routed=False)
    )

    assert view.mode_text == "Legacy"
    assert view.effective_passes_text == "Legacy rule policy"
    assert view.rules_title == "Rules (source policy: 1 instruction, 1 block)"
    assert view.edit_enabled is True


def test_new_config_uses_editable_legacy_strategy() -> None:
    policy = select_config_edit_policy(ConfigEditMode.NEW, None)

    assert policy.allowed is True
    assert policy.rules_editable is True
    assert policy.save_strategy is ConfigSaveStrategy.CREATE_LEGACY


@pytest.mark.parametrize("mode", [ConfigEditMode.EDIT, ConfigEditMode.DUPLICATE])
def test_legacy_edit_and_duplicate_allow_rule_editing(mode: ConfigEditMode) -> None:
    policy = select_config_edit_policy(
        mode,
        _snapshot(mode=ProjectConfigMode.LEGACY, routed=False),
    )

    assert policy.allowed is True
    assert policy.rules_editable is True
    assert policy.save_strategy is ConfigSaveStrategy.SAVE_LEGACY_COPY


def test_config_v2_edit_is_refused() -> None:
    policy = select_config_edit_policy(
        ConfigEditMode.EDIT,
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True),
    )

    assert policy.allowed is False
    assert policy.rules_editable is False
    assert policy.save_strategy is ConfigSaveStrategy.REFUSE
    assert "flat rule tree" in policy.explanation
    assert "pipeline_v2" in policy.explanation


def test_config_v2_duplicate_uses_read_only_runtime_clone() -> None:
    policy = select_config_edit_policy(
        ConfigEditMode.DUPLICATE,
        _snapshot(mode=ProjectConfigMode.CONFIG_V2, routed=True),
    )

    assert policy.allowed is True
    assert policy.rules_editable is False
    assert policy.save_strategy is ConfigSaveStrategy.CLONE_RUNTIME_V2
    assert "effective runtime" in policy.explanation


def test_logic_module_imports_no_ida_or_qt_modules() -> None:
    module_path = Path(project_config_logic.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])

    assert imported_roots.isdisjoint(
        {"idaapi", "ida_kernwin", "ida_hexrays", "PyQt5", "PySide6"}
    )
    assert "qt_shim" not in module_path.read_text(encoding="utf-8")
```

The routed view must produce source and runtime labels separately, preserve full paths as tooltips, and format the rule title with exact instruction/block counts. Assert config-v2 edit refusal text explains that the flat rule tree cannot serialize `pipeline_v2`.

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/ui/test_project_config_logic.py
```

Expected: collection fails because `d810.ui.project_config_logic` does not exist.

- [ ] **Step 3: Implement the pure policy and projection**

Create `src/d810/ui/project_config_logic.py` with this complete implementation:

```python
from __future__ import annotations

import dataclasses
import enum

from d810.manager.project_runtime import (
    ProjectConfigMode,
    ProjectRuntimeSnapshot,
    RuleProjectionKind,
)


V2_EDIT_REFUSAL = (
    "Config-v2 projects are read-only here because the flat rule tree cannot "
    "serialize pipeline_v2 without losing configuration."
)
V2_CLONE_EXPLANATION = (
    "Duplicate will copy the complete effective runtime config-v2 document; "
    "the flat rule tree remains read-only."
)


class ConfigEditMode(str, enum.Enum):
    NEW = "new"
    DUPLICATE = "duplicate"
    EDIT = "edit"


class ConfigSaveStrategy(enum.Enum):
    CREATE_LEGACY = "create-legacy"
    SAVE_LEGACY_COPY = "save-legacy-copy"
    CLONE_RUNTIME_V2 = "clone-runtime-v2"
    REFUSE = "refuse"


@dataclasses.dataclass(frozen=True, slots=True)
class ConfigEditPolicy:
    allowed: bool
    rules_editable: bool
    save_strategy: ConfigSaveStrategy
    explanation: str


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectConfigView:
    mode_text: str
    source_text: str
    source_tooltip: str
    runtime_text: str
    runtime_tooltip: str
    effective_passes_text: str
    rules_title: str
    enabled_rule_names: frozenset[str]
    edit_enabled: bool
    edit_tooltip: str


def select_config_edit_policy(
    mode: ConfigEditMode,
    snapshot: ProjectRuntimeSnapshot | None,
) -> ConfigEditPolicy:
    if mode is ConfigEditMode.NEW:
        return ConfigEditPolicy(
            True,
            True,
            ConfigSaveStrategy.CREATE_LEGACY,
            "",
        )
    if snapshot is None:
        return ConfigEditPolicy(
            False,
            False,
            ConfigSaveStrategy.REFUSE,
            "No active project",
        )
    if mode is ConfigEditMode.EDIT and snapshot.mode is ProjectConfigMode.CONFIG_V2:
        return ConfigEditPolicy(
            False,
            False,
            ConfigSaveStrategy.REFUSE,
            V2_EDIT_REFUSAL,
        )
    if (
        mode is ConfigEditMode.DUPLICATE
        and snapshot.mode is ProjectConfigMode.CONFIG_V2
    ):
        return ConfigEditPolicy(
            True,
            False,
            ConfigSaveStrategy.CLONE_RUNTIME_V2,
            V2_CLONE_EXPLANATION,
        )
    return ConfigEditPolicy(
        True,
        True,
        ConfigSaveStrategy.SAVE_LEGACY_COPY,
        "",
    )


def build_project_config_view(snapshot: ProjectRuntimeSnapshot) -> ProjectConfigView:
    if snapshot.mode is ProjectConfigMode.LEGACY:
        mode_text = "Legacy"
        effective_passes_text = "Legacy rule policy"
    else:
        mode_text = "Config v2 (routed)" if snapshot.routed else "Config v2"
        effective_passes_text = (
            f"{len(snapshot.effective_pass_ids)} passes: "
            + ", ".join(snapshot.effective_pass_ids)
        )

    projection_text = (
        "runtime expansion"
        if snapshot.rule_projection is RuleProjectionKind.RUNTIME_EXPANSION
        else "source policy"
    )
    instruction_count = len(snapshot.effective_instruction_rule_names)
    block_count = len(snapshot.effective_block_rule_names)
    edit_policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
    return ProjectConfigView(
        mode_text=mode_text,
        source_text=snapshot.source.basename,
        source_tooltip=str(snapshot.source.path),
        runtime_text=snapshot.runtime.basename,
        runtime_tooltip=str(snapshot.runtime.path),
        effective_passes_text=effective_passes_text,
        rules_title=(
            f"Rules ({projection_text}: {instruction_count} instruction, "
            f"{block_count} block)"
        ),
        enabled_rule_names=frozenset(
            (*snapshot.effective_instruction_rule_names, *snapshot.effective_block_rule_names)
        ),
        edit_enabled=edit_policy.allowed,
        edit_tooltip=edit_policy.explanation or "Edit legacy rule configuration",
    )
```

- [ ] **Step 4: Verify GREEN and existing action logic**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/ui/test_project_config_logic.py \
  tests/unit/ui/test_actions_logic.py \
  tests/unit/ui/test_export_disasm_logic.py \
  tests/unit/ui/test_export_microcode_logic.py \
  tests/unit/ui/test_export_to_c_logic.py
```

Expected: all tests pass without importing IDA or Qt into the new logic module.

- [ ] **Step 5: Commit the pure UI logic**

```bash
git add src/d810/ui/project_config_logic.py tests/unit/ui/test_project_config_logic.py
git commit -m "feat(ui): add project configuration action logic"
```

---

### Task 4: Make `ida_ui.py` a thin, truthful adapter

**Files:**

- Modify: `src/d810/ui/ida_ui.py:4-19`
- Modify: `src/d810/ui/ida_ui.py:407-449`
- Modify: `src/d810/ui/ida_ui.py:531-612`
- Modify: `src/d810/ui/ida_ui.py:813-979`
- Modify: `src/d810/ui/ida_ui.py:985-1059`
- Create: `tests/unit/ui/test_project_config_adapter_contract.py`

**Interfaces:**

- `D810ConfigForm_t._apply_project_config_view(view: ProjectConfigView) -> None` renders labels, tooltips, button state, rule title, and enabled effective rule names.
- Existing New/Edit/Duplicate/Save callbacks delegate to `select_config_edit_policy()` and the `D810State` manager command facade.
- The form stores the immutable snapshot and source project captured when edit mode begins, then clears both on exit.

- [ ] **Step 1: Write the failing thin-adapter contract test**

Create `tests/unit/ui/test_project_config_adapter_contract.py` with this complete source-level contract:

```python
from __future__ import annotations

import ast
from pathlib import Path


IDA_UI = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "ida_ui.py"
TREE = ast.parse(IDA_UI.read_text(encoding="utf-8"), filename=str(IDA_UI))


def _method(name: str) -> ast.FunctionDef:
    for node in TREE.body:
        if isinstance(node, ast.ClassDef) and node.name == "D810ConfigForm_t":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"D810ConfigForm_t.{name} not found")


def _call_names(method: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def test_load_config_reads_manager_snapshot_and_pure_view() -> None:
    calls = _call_names(_method("_load_config"))

    assert "get_project_runtime_snapshot" in calls
    assert "build_project_config_view" in calls
    assert "_apply_project_config_view" in calls


def test_save_rules_delegates_to_edit_policy_and_manager_commands() -> None:
    calls = _call_names(_method("_save_rules"))

    assert "select_config_edit_policy" in calls
    assert "clone_current_runtime_project" in calls
    assert "save_legacy_project" in calls


def test_save_rules_no_longer_constructs_project_configuration_directly() -> None:
    calls = _call_names(_method("_save_rules"))

    assert "ProjectConfiguration" not in calls


def test_edit_and_duplicate_handlers_use_the_pure_policy() -> None:
    assert "select_config_edit_policy" in _call_names(_method("_edit_config"))
    assert "select_config_edit_policy" in _call_names(_method("_duplicate_config"))


def test_ida_ui_does_not_import_core_project_persistence() -> None:
    imported_modules = {
        node.module
        for node in ast.walk(TREE)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert "d810.core.project_config_persistence" not in imported_modules
```

The test reads source instead of importing the live `ida_ui` module. It therefore enforces the adapter seam without mocking IDA or placing IDA-dependent behavior in unit tests.

- [ ] **Step 2: Verify RED against the current monolithic callback**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/ui/test_project_config_adapter_contract.py
```

Expected: failures because `_load_config()` still renders the source project's flat rules and `_save_rules()` still reconstructs `ProjectConfiguration` directly.

- [ ] **Step 3: Add compact source/runtime presentation widgets**

Add these imports without importing the core persistence module:

```python
from d810.manager import ProjectConfigurationEditError
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigSaveStrategy,
    ProjectConfigView,
    build_project_config_view,
    select_config_edit_policy,
)

# Replace the existing TYPE_CHECKING import block with this combined block.
if typing.TYPE_CHECKING:
    from d810.manager import D810State, ProjectRuntimeSnapshot
```

Change `_edit_mode` to `ConfigEditMode | None` and add these attributes in `__init__`:

```python
self._edit_mode: ConfigEditMode | None = None
self._edit_source_config: ProjectConfiguration | None = None
self._edit_runtime_snapshot: ProjectRuntimeSnapshot | None = None
self._view_rules_title = "Rules"
self._config_mode_value = None
self._config_source_value = None
self._config_runtime_value = None
self._config_passes_value = None
```

Below the existing project selector and above the description, add this compact form layout:

```python
identity_layout = QtWidgets.QFormLayout()
self._config_mode_value = QtWidgets.QLabel()
self._config_source_value = QtWidgets.QLabel()
self._config_runtime_value = QtWidgets.QLabel()
self._config_passes_value = QtWidgets.QLabel()
for value_label in (
    self._config_mode_value,
    self._config_source_value,
    self._config_runtime_value,
    self._config_passes_value,
):
    value_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
self._config_passes_value.setWordWrap(True)
identity_layout.addRow("Mode:", self._config_mode_value)
identity_layout.addRow("Source:", self._config_source_value)
identity_layout.addRow("Runtime:", self._config_runtime_value)
identity_layout.addRow("Effective passes:", self._config_passes_value)
project_vbox.addLayout(identity_layout)
```

Always render Source and Runtime. Do not hide equal values: equality is useful evidence that no routing occurred. Clear the four label references in `OnClose()` with the existing defensive lifecycle pattern.

- [ ] **Step 4: Render the manager snapshot on every project load**

Replace source-project rule derivation in `_load_config()` with:

```python
project = self.state.load_project(index)
snapshot = self.state.get_project_runtime_snapshot()
view = build_project_config_view(snapshot)
self.cfg_description.setPlainText(project.description)
self._apply_project_config_view(view)
```

Add this assignment-only renderer before `_load_config()`:

```python
def _apply_project_config_view(self, view: ProjectConfigView) -> None:
    self._config_mode_value.setText(view.mode_text)
    self._config_source_value.setText(view.source_text)
    self._config_source_value.setToolTip(view.source_tooltip)
    self._config_runtime_value.setText(view.runtime_text)
    self._config_runtime_value.setToolTip(view.runtime_tooltip)
    self._config_passes_value.setText(view.effective_passes_text)
    self.btn_edit_cfg.setEnabled(view.edit_enabled)
    self.btn_edit_cfg.setToolTip(view.edit_tooltip)
    self._view_rules_title = view.rules_title
    if self._edit_mode is None:
        self._rules_group.setTitle(view.rules_title)
    self._rule_tree.set_enabled_rules(set(view.enabled_rule_names))
```

- [ ] **Step 5: Route New/Edit/Duplicate through the pure policy**

Extend `_enter_edit_mode()` with these parameters and assignments while retaining the existing rule-config extraction and group enable/disable code:

```python
def _enter_edit_mode(
    self,
    mode: ConfigEditMode,
    description: str,
    ins_rules: list[RuleConfiguration],
    blk_rules: list[RuleConfiguration],
    path: pathlib.Path | None,
    source_config: ProjectConfiguration | None,
    snapshot: ProjectRuntimeSnapshot | None,
    rules_editable: bool,
    enabled_rule_names: frozenset[str] | None = None,
) -> None:
    self._edit_mode = mode
    self._edit_path = path
    self._edit_old_conf = source_config if mode is ConfigEditMode.EDIT else None
    self._edit_source_config = source_config
    self._edit_runtime_snapshot = snapshot

    enabled_names: set[str] = set(enabled_rule_names or ())
    self._rule_configs.clear()
    for rule_config in (*ins_rules, *blk_rules):
        if rule_config.is_activated:
            enabled_names.add(str(rule_config.name))
        if rule_config.config and rule_config.name:
            self._rule_configs[rule_config.name] = dict(rule_config.config)
    self._rule_tree.set_enabled_rules(enabled_names)
    self._rule_tree.set_read_only(not rules_editable)
    self._rule_detail.set_read_only(not rules_editable)
```

Keep the remainder of the current method, changing the mode comparisons to enum identity checks. Replace the unconditional editing title with:

```python
self._rules_group.setTitle(
    "Rules (editing)" if rules_editable else self._view_rules_title
)
```

In `_exit_edit_mode()`, restore `self._rules_group.setTitle(self._view_rules_title)` and clear `_edit_source_config` plus `_edit_runtime_snapshot`.

Replace the three entry callbacks with:

```python
def _create_config(self) -> None:
    policy = select_config_edit_policy(ConfigEditMode.NEW, None)
    self._enter_edit_mode(
        ConfigEditMode.NEW,
        "",
        [],
        [],
        None,
        None,
        None,
        policy.rules_editable,
    )

def _duplicate_config(self) -> None:
    snapshot = self.state.get_project_runtime_snapshot()
    policy = select_config_edit_policy(ConfigEditMode.DUPLICATE, snapshot)
    if not policy.allowed:
        QtWidgets.QMessageBox.information(
            self.parent,
            "Configuration cannot be duplicated",
            policy.explanation,
        )
        return
    current = self.state.current_project
    view = build_project_config_view(snapshot)
    is_runtime_clone = policy.save_strategy is ConfigSaveStrategy.CLONE_RUNTIME_V2
    self._enter_edit_mode(
        ConfigEditMode.DUPLICATE,
        "Duplicate of " + current.description,
        [] if is_runtime_clone else current.ins_rules,
        [] if is_runtime_clone else current.blk_rules,
        None,
        current,
        snapshot,
        policy.rules_editable,
        view.enabled_rule_names if is_runtime_clone else None,
    )

def _edit_config(self) -> None:
    snapshot = self.state.get_project_runtime_snapshot()
    policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
    if not policy.allowed:
        QtWidgets.QMessageBox.information(
            self.parent,
            "Configuration is read-only",
            policy.explanation,
        )
        return
    current = self.state.current_project
    self._enter_edit_mode(
        ConfigEditMode.EDIT,
        current.description,
        current.ins_rules,
        current.blk_rules,
        current.path,
        current,
        snapshot,
        policy.rules_editable,
    )
```

Do not infer editability from button state inside `_save_rules()`.

- [ ] **Step 6: Replace reconstructive saves with manager commands**

Change the save-path comparisons to `ConfigEditMode.NEW`, `ConfigEditMode.DUPLICATE`, and `ConfigEditMode.EDIT`. After building `ins_rules` and `blk_rules`, re-evaluate the captured policy and execute the manager command inside one error boundary:

```python
if self._edit_mode is None:
    logger.error("Cannot save without an edit mode")
    return
policy = select_config_edit_policy(self._edit_mode, self._edit_runtime_snapshot)
if not policy.allowed or policy.save_strategy is ConfigSaveStrategy.REFUSE:
    QtWidgets.QMessageBox.warning(self.parent, "Configuration not saved", policy.explanation)
    return

try:
    if policy.save_strategy is ConfigSaveStrategy.CLONE_RUNTIME_V2:
        new_config = self.state.clone_current_runtime_project(save_path, description)
    else:
        new_config = self.state.save_legacy_project(
            snapshot=self._edit_runtime_snapshot,
            source=self._edit_source_config,
            destination=save_path,
            description=description,
            ins_rules=ins_rules,
            blk_rules=blk_rules,
        )
except ProjectConfigurationEditError as exc:
    QtWidgets.QMessageBox.critical(
        self.parent,
        "Configuration not saved",
        str(exc),
    )
    return
```

For New, `_edit_source_config` and `_edit_runtime_snapshot` are `None`. For legacy Edit/Duplicate, they are the complete selected source project and immutable snapshot. For config-v2 Duplicate, `clone_current_runtime_project()` resolves `current_runtime_project` inside the manager facade and never clones `current_project`. Catch the manager's `ProjectConfigurationEditError`, show an error dialog, and leave edit mode active so the user can retry. `ida_ui.py` must not import `d810.core.project_config_persistence`.

Keep existing `state.add_project()` versus `state.update_project()` semantics. After success, reload the saved selection and rebuild the manager snapshot before exiting edit mode so title/button state cannot remain stale.

- [ ] **Step 7: Verify the adapter and all focused UI logic**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/ui/test_project_config_adapter_contract.py \
  tests/unit/ui/test_project_config_logic.py \
  tests/unit/core/test_project_config_persistence.py \
  tests/unit/manager/test_project_runtime.py
```

Expected: all tests pass; the adapter contract proves the widget no longer owns config-v2 save or projection policy.

- [ ] **Step 8: Commit the Qt adapter**

```bash
git add src/d810/ui/ida_ui.py tests/unit/ui/test_project_config_adapter_contract.py
git commit -m "feat(ui): render truthful config-v2 projects"
```

---

### Task 5: Lock the bundled OLLVM round trip end to end

**Files:**

- Create: `tests/unit/ui/test_project_config_ollvm_regression.py`
- Reference: `src/d810/conf/default_unflattening_ollvm.json`
- Reference: `src/d810/conf/default_unflattening_ollvm_config_v2_canary.json`
- Reference: `tests/unit/core/test_config_v2_defaults.py:43-97`
- Reference: `tests/unit/passes/test_pipeline_v2_hook_bridge.py:112-126`

**Interfaces:**

- Consumes: bundled source selection, routed runtime, hook activation, manager snapshot, pure UI view, and lossless persistence.
- Produces: one executable regression proving the UI cannot report zero active behavior or flatten away the config-v2 payload.

- [ ] **Step 1: Write the cross-layer OLLVM witness**

Create `tests/unit/ui/test_project_config_ollvm_regression.py` with this complete witness:

```python
from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import select_config_v2_default_project
from d810.core.project_config_persistence import clone_project_configuration
from d810.manager.project_runtime import (
    ProjectConfigMode,
    RuleProjectionKind,
    build_project_runtime_snapshot,
)
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigSaveStrategy,
    build_project_config_view,
    select_config_edit_policy,
)


CONF_DIR = Path("src/d810/conf")
EXPECTED_PASS_IDS = (
    "mba-simplify",
    "materialized-computed-goto-island",
    "indirect-call-resolver",
    "mba-state-preconditioner",
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
    "simple-flattening-cleanup-unflattener",
    "jump-fixer",
)


def test_ollvm_routing_view_and_lossless_user_duplicate(tmp_path: Path) -> None:
    source = ProjectConfiguration.from_file(
        CONF_DIR / "default_unflattening_ollvm.json"
    )
    selection = select_config_v2_default_project(source)
    assert selection is not None
    activation = pipeline_v2_hook_activation(selection.runtime_project)
    snapshot = build_project_runtime_snapshot(
        source_project=source,
        runtime_project=selection.runtime_project,
        default_selection=selection,
        hook_activation=activation,
        hook_mode="config-v2",
    )
    view = build_project_config_view(snapshot)

    assert snapshot.source.basename == "default_unflattening_ollvm.json"
    assert snapshot.runtime.basename == (
        "default_unflattening_ollvm_config_v2_canary.json"
    )
    assert snapshot.routed is True
    assert snapshot.mode is ProjectConfigMode.CONFIG_V2
    assert snapshot.rule_projection is RuleProjectionKind.RUNTIME_EXPANSION
    assert snapshot.effective_pass_ids == EXPECTED_PASS_IDS
    assert len(snapshot.effective_instruction_rule_names) == 180
    assert len(snapshot.effective_block_rule_names) == 6
    assert view.mode_text == "Config v2 (routed)"
    assert view.effective_passes_text.startswith("11 passes: ")
    assert view.rules_title == "Rules (runtime expansion: 180 instruction, 6 block)"
    assert len(view.enabled_rule_names) == 186

    edit_policy = select_config_edit_policy(ConfigEditMode.EDIT, snapshot)
    duplicate_policy = select_config_edit_policy(ConfigEditMode.DUPLICATE, snapshot)
    assert edit_policy.save_strategy is ConfigSaveStrategy.REFUSE
    assert duplicate_policy.save_strategy is ConfigSaveStrategy.CLONE_RUNTIME_V2
    assert duplicate_policy.rules_editable is False

    destination = tmp_path / "ollvm-user-copy.json"
    duplicate = clone_project_configuration(
        source=selection.runtime_project,
        destination=destination,
        description="OLLVM user copy",
    )
    expected_document = json.loads(
        selection.runtime_project.path.read_text(encoding="utf-8")
    )
    expected_document["description"] = "OLLVM user copy"
    assert json.loads(destination.read_text(encoding="utf-8")) == expected_document
    assert duplicate.additional_configuration == (
        selection.runtime_project.additional_configuration
    )
    assert select_config_v2_default_project(duplicate) is None

    duplicate_activation = pipeline_v2_hook_activation(duplicate)
    assert duplicate_activation.enabled is True
    assert duplicate_activation.configured_pass_ids == EXPECTED_PASS_IDS
    assert len(duplicate_activation.instruction_rules) == 180
    assert len(duplicate_activation.block_rules) == 6
```

- [ ] **Step 2: Verify the witness fails before all Slice 0 seams are present**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/ui/test_project_config_ollvm_regression.py
```

Expected: RED if any persistence, snapshot, or pure UI seam is still missing or wired incorrectly.

- [ ] **Step 3: Make only fixture-truth corrections**

If the expected pass tuple or 180/6 counts differ, stop and inspect the checked-in canary plus `pipeline_v2_hook_activation()`. Update the test only when an intentional fixture change is part of the same commit. Do not weaken assertions to `> 0`.

- [ ] **Step 4: Verify GREEN with neighboring routing/bridge tests**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/ui/test_project_config_ollvm_regression.py \
  tests/unit/core/test_config_v2_defaults.py \
  tests/unit/passes/test_pipeline_v2_hook_bridge.py
```

Expected: all tests pass with the exact 11-pass, 180-instruction-rule, 6-block-rule witness.

- [ ] **Step 5: Commit the regression**

```bash
git add tests/unit/ui/test_project_config_ollvm_regression.py
git commit -m "test(ui): lock OLLVM config-v2 round trip"
```

---

### Task 6: Run architecture, regression, graph, and live-UI acceptance gates

**Files:**

- Modify if generated: `graphify-out/*`
- Update: `.tickets/d81-kcin.md`

**Interfaces:**

- Consumes: the completed Slice 0 implementation.
- Produces: verified architecture boundaries, a final unit regression result, refreshed graph metadata, and a live IDA acceptance record.

- [ ] **Step 1: Run the complete focused suite**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest -q \
  tests/unit/core/test_config.py \
  tests/unit/core/test_project_config_persistence.py \
  tests/unit/core/test_config_v2_defaults.py \
  tests/unit/manager/test_project_runtime.py \
  tests/unit/passes/test_pipeline_v2_hook_bridge.py \
  tests/unit/ui/test_project_config_logic.py \
  tests/unit/ui/test_project_config_adapter_contract.py \
  tests/unit/ui/test_project_config_ollvm_regression.py
```

Expected: all selected tests pass.

- [ ] **Step 2: Run architecture and whitespace gates from the implementation worktree**

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
```

Expected: zero ast-grep errors, all import-linter contracts kept, and no whitespace errors. Do not add ignores to make a failure green.

- [ ] **Step 3: Run the final full unit suite once**

```bash
PYTHONPATH=src:tests pyenv exec python -m pytest tests/unit/ -q --tb=short
```

Expected: pass. This is the second and final full-unit run for the implementation session.

- [ ] **Step 4: Re-run the executable OLLVM manifest probe**

```bash
PYTHONPATH=src pyenv exec python -c "from pathlib import Path; from d810.core.config import ProjectConfiguration; from d810.core.config_v2_defaults import select_config_v2_default_project; from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation; source=ProjectConfiguration.from_file(Path('src/d810/conf/default_unflattening_ollvm.json').resolve()); selection=select_config_v2_default_project(source); activation=pipeline_v2_hook_activation(selection.runtime_project); print(selection.source_project.path.name, selection.runtime_project.path.name, selection.routed); print(len(activation.configured_pass_ids), activation.configured_pass_ids); print(len(activation.instruction_rules), len(activation.block_rules))"
```

Expected output values: routed `True`, 11 ordered pass IDs, 180 instruction rules, and 6 block rules.

- [ ] **Step 5: Refresh the code graph**

```bash
graphify update .
git status --short
```

Review graph changes and include only generated graph metadata caused by Slice 0. Do not absorb unrelated worktree changes.

- [ ] **Step 6: Perform live IDA acceptance**

In a supported IDA GUI:

1. Open the existing D-810 Configuration form.
2. Select `default_unflattening_ollvm.json`.
3. Verify Mode is `Config v2 (routed)`.
4. Verify Source and Runtime show their distinct basenames and full-path tooltips.
5. Verify Effective passes shows 11 ordered IDs.
6. Verify the Rules title says runtime expansion with 180 instruction and 6 block rules and the tree is not empty.
7. Verify Edit is disabled/refused with the config-v2 explanation.
8. Duplicate to a user path, changing only the description.
9. Select the duplicate and verify Source equals Runtime, Mode is `Config v2`, routing is false, and the 11/180/6 behavior is unchanged.
10. Open the duplicated JSON in an editor and verify `additional_configuration.pipeline_v2`, fact-profile modules, migration metadata, and pass options remain present.

Record the IDA version, Qt binding, duplicate path, and observed labels/counts in `tk add-note d81-kcin`. If live IDA is unavailable, leave the ticket open and report this gate explicitly; do not call Slice 0 complete based only on unit tests.

- [ ] **Step 7: Finalize ticket and commit generated metadata**

After every automated and live gate passes:

```bash
tk add-note d81-kcin "Slice 0 verified: lossless atomic persistence, immutable source/runtime snapshot, pure UI action logic, thin Qt adapter, exact OLLVM 11/180/6 witness, architecture gates, full unit suite, and live IDA acceptance."
tk close d81-kcin
git add .tickets/d81-kcin.md graphify-out
git commit -m "chore(ui): finalize truthful config-v2 slice"
```

Before handoff, invoke `superpowers:verification-before-completion`, `superpowers:requesting-code-review`, and the Simba lifecycle finalizer. Report any retained manual gate or pre-existing baseline failure instead of closing the ticket.

"""Binary patching helpers for dispatcher unflattening.

This module provides data structures to record and apply control‑flow
patches to the binary.  After a dispatcher has been identified and
simplified, the plugin can either modify the micro‑code (which is
ephemeral) or patch the actual binary instructions.  By converting
micro‑code jumps back into assembly and rewriting the corresponding
bytes, the control flow becomes permanently simplified and survives
reanalysis.  Patch descriptions are stored in a simple serialisable
format so that they can be persisted to disk and reapplied on future
sessions.

These helpers do not perform any IDA‑specific operations on their own.
Instead, they encapsulate patch actions which can later be executed
when the Hex‑Rays/IDA environment is available.  The :class:`BinaryPatcher`
class shows how one might apply these actions using IDA APIs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Dict, Optional


@dataclass
class PatchAction:
    """Represents a single binary patch action.

    Attributes
    ----------
    action : str
        The type of patch action (e.g. "replace", "delete", "rename").
    target_block_serial : int
        The serial number of the micro‑code block to which the patch
        applies.  When converting to assembly, this serial should be
        mapped to an address.
    params : dict
        Additional parameters required by the patch.  For a ``replace``
        action, ``params`` might contain a "jump_target" key specifying
        the destination block serial.
    """

    action: str
    target_block_serial: int
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "target_block_serial": self.target_block_serial,
            "params": self.params,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PatchAction":
        return cls(
            action=data.get("action", ""),
            target_block_serial=data.get("target_block_serial", -1),
            params=dict(data.get("params", {})),
        )


@dataclass
class PatchRecorder:
    """Collects patch actions produced during unflattening."""

    actions: List[PatchAction] = field(default_factory=list)

    def record_replace(self, block_serial: int, jump_target_serial: int) -> None:
        """Record a replace action which will replace the block with an unconditional jump."""
        self.actions.append(
            PatchAction(
                action="replace",
                target_block_serial=block_serial,
                params={"jump_target": jump_target_serial},
            )
        )

    def record_delete(self, block_serial: int) -> None:
        """Record a delete action to remove a dead block."""
        self.actions.append(
            PatchAction(
                action="delete",
                target_block_serial=block_serial,
                params={},
            )
        )

    def record_rename(self, old_serial: int, new_name: str) -> None:
        """Record a rename action for a state variable or symbol."""
        self.actions.append(
            PatchAction(
                action="rename",
                target_block_serial=old_serial,
                params={"new_name": new_name},
            )
        )

    def to_dict(self) -> dict:
        return {"actions": [a.to_dict() for a in self.actions]}

    @classmethod
    def from_dict(cls, data: dict) -> "PatchRecorder":
        pr = cls()
        for a in data.get("actions", []):
            pr.actions.append(PatchAction.from_dict(a))
        return pr


class BinaryPatcher:
    """Applies recorded patch actions using IDA APIs.

    This class provides a thin wrapper around IDA Pro functions such as
    ``ida_bytes.patch_bytes`` or ``idaapi.convert_to_jump``.  It is
    intentionally lightweight: the heavy lifting of deciding which
    blocks to patch is done during unflattening, and this class simply
    executes the recorded actions.  When running outside of IDA, the
    ``apply`` method will do nothing.
    """

    def __init__(self, patch_recorder: PatchRecorder):
        self.recorder = patch_recorder

    def apply(self) -> None:
        """Apply all recorded patches to the binary.

        When IDA APIs are available, the actions will be executed.  If
        running outside of IDA, this method logs the intended
        operations but performs no changes.
        """
        try:
            import ida_bytes
            import idaapi
        except Exception:
            # No IDA environment; print debug output instead
            for act in self.recorder.actions:
                print(f"[BinaryPatcher] Would apply {act.action} to block {act.target_block_serial} with params {act.params}")
            return
        # IDA environment: actual patching logic goes here
        for act in self.recorder.actions:
            if act.action == "replace":
                # Replace the block with an unconditional jump to the target
                # In a real implementation, we would compute the address of
                # the target block and emit the appropriate jump opcode.
                # For example:
                # addr = get_block_address(act.target_block_serial)
                # ida_bytes.patch_byte(addr, ...)
                # idaapi.create_insn(addr)
                pass  # TODO: implement actual patching logic
            elif act.action == "delete":
                # Delete the block by patching NOPs or deleting code
                pass  # TODO: implement deletion logic
            elif act.action == "rename":
                # Rename a symbol or variable
                pass  # TODO: implement rename logic
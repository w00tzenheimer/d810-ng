"""Portable SQLite-backed mining and explicit review materialization."""

from __future__ import annotations

import hashlib
import json
import math
import ctypes
import errno
import os
import stat
import sys
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from d810.mba.bounded_synthesis import (
    MbaSynthesisBudget,
    MbaSynthesisResult,
    synthesize_residual,
)
from d810.mba.discovery_models import (
    ClaimReceipt,
    MiningClaim,
    ProposalState,
    ReceiptStatus,
)
from d810.mba.discovery_store import (
    DISCOVERY_LEASE_TIMEOUT_SECONDS,
    MbaDiscoveryStore,
    decode_proposal_payload,
)
from d810.mba.rule_proposal import MbaRuleProposal, render_rule_source
from d810.mba.subterm_atomization import AtomizedMbaTerm, atomize_repeated_subterms
from d810.mba.term_codec import typed_term_to_dict
from d810.mba.typed_term import term_fingerprint


@dataclass(frozen=True, slots=True)
class MineOutcome:
    """One bounded claim outcome suitable for deterministic CLI reporting."""

    status: str
    reason: str | None = None
    proposal: MbaRuleProposal | None = None
    proposal_id: str | None = None


class _HeartbeatCoordinator:
    def __init__(self, store: MbaDiscoveryStore, claim: MiningClaim, interval: float) -> None:
        self._store = store
        self._claim = claim
        self._interval = interval
        self._stop = threading.Event()
        self._error: BaseException | None = None
        self._refusal: str | None = None
        self._thread = threading.Thread(
            target=self._run,
            name=f"d810-mba-heartbeat-{claim.run.run_id}",
            daemon=True,
        )

    def _run(self) -> None:
        try:
            while not self._stop.wait(self._interval):
                receipt = self._store.heartbeat(
                    self._claim.run.run_id, self._claim.run.claimed_revision
                )
                if receipt.status is not ReceiptStatus.HEARTBEATED:
                    self._refusal = receipt.reason or receipt.status.value
                    return
        except BaseException as exc:
            self._error = exc

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> tuple[str | None, BaseException | None, bool]:
        self._stop.set()
        # heartbeat() bounds both the Python serialization lock and SQLite's
        # writer wait.  Wait for that bounded operation to leave the store
        # before the caller can return or close it.
        self._thread.join()
        return self._refusal, self._error, not self._thread.is_alive()


def budget_fingerprint(budget: MbaSynthesisBudget) -> str:
    """Return the stable identity of one synthesis budget."""

    if not isinstance(budget, MbaSynthesisBudget):
        raise TypeError("budget must be an MbaSynthesisBudget")
    payload = {
        name: getattr(budget, name)
        for name in (
            "max_atoms",
            "max_variables",
            "max_candidate_operator_nodes",
            "max_generated_terms",
            "max_candidate_attempts",
            "witness_count",
        )
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(("mba-discovery-budget-v1:" + encoded).encode("ascii")).hexdigest()


def _json_ready(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value


def _proposal_for(
    claim: MiningClaim,
    atomized: AtomizedMbaTerm,
    result: MbaSynthesisResult,
) -> MbaRuleProposal:
    if result.replacement is None or not result.certified:
        raise ValueError("cannot create proposal from uncertified synthesis")
    restored = atomized.restore(result.replacement)
    source_fingerprint = term_fingerprint(claim.group.canonical_term)
    class_name = "MbaResidualRule_" + hashlib.sha256(
        source_fingerprint.encode("ascii")
    ).hexdigest()[:12]
    fixture = {
        "original": typed_term_to_dict(atomized.original_term),
        "atomized": typed_term_to_dict(atomized.atomized_term),
        "certified_atomized_replacement": typed_term_to_dict(result.replacement),
        "restored_replacement": typed_term_to_dict(restored),
        "atomization_bindings": [
            {
                "leaf_key": list(binding.leaf_key),
                "original_subterm": typed_term_to_dict(binding.original_subterm),
                "occurrence_count": binding.occurrence_count,
                "saved_operator_nodes": binding.saved_operator_nodes,
            }
            for binding in atomized.bindings
        ],
        "proof_widths": [receipt.width for receipt in result.proof_receipts],
        "source_fingerprint": source_fingerprint,
    }
    return MbaRuleProposal(
        proposal_fingerprint=None,
        source_fingerprints=(
            source_fingerprint,
        ),
        occurrence_count=claim.group.eligible_observation_count,
        pattern=result.source,
        replacement=result.replacement,
        source_cost=result.source_cost,
        replacement_cost=result.replacement_cost,
        atomization_bindings=atomized.bindings,
        proof_receipts=result.proof_receipts,
        class_name=class_name,
        family=result.replacement.operation or result.source.operation or "residual",
        description="Proof-certified simplification discovered from an MBA residual",
        provenance=(
            f"discovery_db:group:{claim.group.group_id}:revision:{claim.run.claimed_revision}",
        ),
        fixture=fixture,
        fixed_operation_descriptors=result.fixed_operation_descriptors,
        synthesis_result=result,
    )


class DiscoveryMiner:
    """Mine one store claim at a time without producing filesystem artifacts."""

    def __init__(
        self,
        store: MbaDiscoveryStore,
        *,
        miner_version: str = "d810-discovery-miner-v1",
        budget: MbaSynthesisBudget | None = None,
        atomizer: Callable[..., AtomizedMbaTerm] = atomize_repeated_subterms,
        synthesizer: Callable[..., MbaSynthesisResult] = synthesize_residual,
        heartbeat_interval: float | None = None,
    ) -> None:
        if not isinstance(store, MbaDiscoveryStore):
            raise TypeError("store must be an MbaDiscoveryStore")
        if type(miner_version) is not str or not miner_version or miner_version.strip() != miner_version:
            raise ValueError("miner_version must be a canonical non-empty string")
        self.store = store
        self.miner_version = miner_version
        self.budget = MbaSynthesisBudget() if budget is None else budget
        if not isinstance(self.budget, MbaSynthesisBudget):
            raise TypeError("budget must be an MbaSynthesisBudget")
        self.atomizer = atomizer
        self.synthesizer = synthesizer
        self.heartbeat_interval = (
            DISCOVERY_LEASE_TIMEOUT_SECONDS / 2
            if heartbeat_interval is None
            else heartbeat_interval
        )
        if (
            type(self.heartbeat_interval) not in (int, float)
            or not math.isfinite(float(self.heartbeat_interval))
            or self.heartbeat_interval <= 0
        ):
            raise ValueError("heartbeat_interval must be positive")

    def claim(self) -> ClaimReceipt:
        """Claim the next eligible group using this miner's stable identity."""

        return self.store.claim_next_group(
            self.miner_version, budget_fingerprint(self.budget)
        )

    def mine_claim(
        self, claim: MiningClaim, budget: MbaSynthesisBudget | None = None
    ) -> MineOutcome:
        if not isinstance(claim, MiningClaim):
            raise TypeError("claim must be a MiningClaim")
        selected_budget = self.budget if budget is None else budget
        if not isinstance(selected_budget, MbaSynthesisBudget):
            raise TypeError("budget must be an MbaSynthesisBudget")
        if claim.run.budget_fingerprint != budget_fingerprint(selected_budget):
            return MineOutcome("refused", "budget_fingerprint_mismatch")
        if not claim.group.raw_terms:
            return MineOutcome("refused", "empty_raw_evidence")

        coordinator = _HeartbeatCoordinator(
            self.store, claim, float(self.heartbeat_interval)
        )
        coordinator.start()
        stopped_cleanly = False
        try:
            atomized = self.atomizer(
                claim.group.raw_terms[0], max_atoms=selected_budget.max_atoms
            )
            result = self.synthesizer(atomized, budget=selected_budget)
            refusal, error, stopped_cleanly = coordinator.stop()
            if not stopped_cleanly:
                return MineOutcome("error", "heartbeat_worker_did_not_stop")
            if error is not None:
                return MineOutcome("error", f"heartbeat_error: {type(error).__name__}: {error}")
            if refusal is not None:
                return MineOutcome("refused", refusal)
            if result.certified:
                proposal = _proposal_for(claim, atomized, result)
                receipt = self.store.publish_proposal(
                    claim.run.run_id,
                    claim.run.claimed_revision,
                    proposal,
                    proposal.replacement,
                    proposal,
                )
                if receipt.status in (ReceiptStatus.PUBLISHED, ReceiptStatus.DUPLICATE):
                    return MineOutcome(
                        "published",
                        receipt.status.value,
                        proposal,
                        None if receipt.proposal is None else receipt.proposal.proposal_id,
                    )
                return MineOutcome("refused", receipt.reason or receipt.status.value)
            reason = (
                result.exhaustion.reason
                if result.exhaustion is not None
                else "proof_failed"
            )
            finished = self.store.finish_no_proposal(
                claim.run.run_id, claim.run.claimed_revision, reason
            )
            if finished.status is ReceiptStatus.FINISHED:
                return MineOutcome("no_proposal", reason)
            return MineOutcome("refused", finished.reason or finished.status.value)
        except Exception as exc:
            return MineOutcome("error", f"{type(exc).__name__}: {exc}")
        finally:
            if not stopped_cleanly:
                _refusal, _error, stopped_cleanly = coordinator.stop()


def _digest_files(files: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(files):
        relative = name.encode("utf-8")
        content = files[name]
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _read_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _tree_digest(root: Path) -> str:
    """Digest a tree through no-follow descriptors, never symlink targets."""

    root = Path(root)
    root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        files: dict[str, bytes] = {}
        for name in sorted(os.listdir(root_fd)):
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("materialization tree contains a non-regular entry")
                files[name] = _read_fd(fd)
            finally:
                os.close(fd)
        return _digest_files(files)
    finally:
        os.close(root_fd)


def _open_dir(path: Path) -> int:
    """Open an existing directory path with no-follow traversal."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    anchor = path.anchor or "."
    fd = os.open(anchor, flags)
    try:
        parts = path.parts[1:] if path.anchor else path.parts
        for component in parts:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_at(directory_fd: int, name: str, flags: int) -> int:
    return os.open(name, flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)


def _verify_parent_path(path: Path, parent_fd: int) -> None:
    """Ensure the lexical parent still names the descriptor-anchored inode."""

    current_fd = _open_dir(path)
    try:
        expected = os.fstat(parent_fd)
        current = os.fstat(current_fd)
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise FileExistsError("materialization parent path was replaced")
    finally:
        os.close(current_fd)


def _mkdtemp_at(parent_fd: int, prefix: str) -> str:
    """Create a private, mode-700 temporary directory beneath ``parent_fd``."""

    # ``tempfile.mkdtemp`` has no dir-fd form.  Keep its random-name and
    # exclusive-mkdir semantics while making the parent anchor explicit.
    for _ in range(128):
        name = f"{prefix}{uuid.uuid4().hex}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        return name
    raise FileExistsError("unable to allocate a private staging directory")


def _exclusive_rename(directory_fd: int, source: str, destination: str) -> None:
    """Publish or quarantine one directory without replacing its destination."""

    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        function = getattr(libc, "renameat2", None)
        if function is None:
            raise OSError(errno.ENOTSUP, "renameat2 is unavailable")
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(directory_fd, os.fsencode(source), directory_fd, os.fsencode(destination), 1)
    elif sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        function = getattr(libc, "renameatx_np", None)
        if function is None:
            raise OSError(errno.ENOTSUP, "renameatx_np is unavailable")
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(directory_fd, os.fsencode(source), directory_fd, os.fsencode(destination), 0x00000004)
    elif os.name == "nt":
        raise OSError(errno.ENOTSUP, "exclusive directory rename is unavailable")
    else:
        raise OSError(errno.ENOTSUP, "exclusive directory rename is unsupported")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _inspect_tree(
    directory_fd: int,
    directory_path: Path,
    expected: Mapping[str, bytes],
    *,
    fsync_files: bool,
) -> tuple[str, dict[str, tuple[int, int]]]:
    names = tuple(sorted(os.listdir(directory_fd)))
    if names != tuple(sorted(expected)):
        raise FileExistsError("output tree conflicts with existing artifacts")
    identities: dict[str, tuple[int, int]] = {}
    for name, content in expected.items():
        try:
            fd = _open_at(directory_fd, name, os.O_RDONLY)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise FileExistsError("materialization artifact cannot be a symlink") from exc
            raise
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise FileExistsError("materialization artifact is not regular")
            actual = _read_fd(fd)
            if actual != content:
                raise FileExistsError("output tree conflicts with existing artifacts")
            if fsync_files:
                os.fsync(fd)
            identities[name] = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)
    return _digest_files(expected), identities


def _delete_exact_tree(directory_fd: int, directory_path: Path, expected: Mapping[str, bytes], identities: Mapping[str, tuple[int, int]]) -> None:
    names = tuple(sorted(os.listdir(directory_fd)))
    if names != tuple(sorted(expected)):
        raise RuntimeError("materialization recovery conflict")
    for name, content in expected.items():
        fd = _open_at(directory_fd, name, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != identities[name] or _read_fd(fd) != content:
                raise RuntimeError("materialization recovery conflict")
        finally:
            os.close(fd)
    for name in expected:
        os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _remove_private_tree(parent_fd: int, parent_path: Path, name: str) -> None:
    try:
        directory_fd = _open_at(parent_fd, name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except FileNotFoundError:
        return
    try:
        for child_name in tuple(os.listdir(directory_fd)):
            try:
                child_fd = _open_at(directory_fd, child_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            except NotADirectoryError:
                os.unlink(child_name, dir_fd=directory_fd)
                continue
            try:
                _remove_private_tree(directory_fd, parent_path / name, child_name)
            finally:
                os.close(child_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _retained_quarantine_error(
    parent_path: Path, output_name: str, quarantine_name: str
) -> RuntimeError:
    visible_path = os.path.normpath(
        os.path.abspath(os.fspath(parent_path / output_name))
    )
    quarantine_path = os.path.normpath(
        os.path.abspath(os.fspath(parent_path / quarantine_name))
    )
    return RuntimeError(
        "materialization recovery conflict: visible destination preserved at "
        f"{visible_path}; quarantined owned tree retained at {quarantine_path}"
    )


def _quarantine_owned_tree(
    parent_fd: int,
    parent_path: Path,
    output_name: str,
    expected: Mapping[str, bytes],
    root_identity: tuple[int, int],
    child_identities: Mapping[str, tuple[int, int]],
) -> None:
    try:
        current_fd = _open_at(parent_fd, output_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except FileNotFoundError:
        return
    try:
        current_info = os.fstat(current_fd)
        if (current_info.st_dev, current_info.st_ino) != root_identity:
            return
    finally:
        os.close(current_fd)
    quarantine_name = f".{output_name}.quarantine-{uuid.uuid4().hex}"
    try:
        _exclusive_rename(parent_fd, output_name, quarantine_name)
    except FileNotFoundError:
        return
    quarantine_fd = None
    try:
        quarantine_fd = _open_at(
            parent_fd,
            quarantine_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        info = os.fstat(quarantine_fd)
        if (info.st_dev, info.st_ino) != root_identity:
            raise RuntimeError("materialization recovery conflict")
        _delete_exact_tree(
            quarantine_fd, parent_path / quarantine_name, expected, child_identities
        )
    except BaseException as exc:
        # Restore every inspection/open/type/content failure before exposing the
        # original error.  A racing destination is never replaced; the private
        # quarantine remains for explicit recovery instead.
        try:
            _exclusive_rename(parent_fd, quarantine_name, output_name)
        except BaseException as restore_exc:
            raise _retained_quarantine_error(
                parent_path, output_name, quarantine_name
            ) from restore_exc
        os.fsync(parent_fd)
        raise RuntimeError("materialization recovery conflict") from exc
    finally:
        if quarantine_fd is not None:
            os.close(quarantine_fd)
    try:
        os.rmdir(quarantine_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except BaseException as exc:
        try:
            _exclusive_rename(parent_fd, quarantine_name, output_name)
        except BaseException as restore_exc:
            raise _retained_quarantine_error(
                parent_path, output_name, quarantine_name
            ) from restore_exc
        os.fsync(parent_fd)
        raise RuntimeError("materialization recovery conflict") from exc


def _reject_symlink_components(path: Path) -> None:
    """Reject any existing symlink in the lexical output path."""

    current = Path(path.anchor) if path.anchor else Path()
    for component in path.parts:
        if component == path.anchor:
            continue
        current /= component
        if os.path.lexists(current) and stat.S_ISLNK(os.lstat(current).st_mode):
            raise FileExistsError("output path cannot contain symlinks")


def _fixture_json(value: Mapping[str, object]) -> str:
    return json.dumps(_json_ready(value), allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def _reconcile_materialization_error(
    store: MbaDiscoveryStore,
    proposal_id: str,
    path: str,
    digest: str,
    error: BaseException,
) -> None:
    """Attach public-store outcome context without authorizing tree deletion."""

    try:
        snapshot = store.proposal_snapshot(proposal_id)
    except BaseException as reconciliation_error:
        error.add_note(
            "materialization commit outcome could not be reconciled through "
            "proposal_snapshot(); exact artifact tree preserved for adoption: "
            f"{type(reconciliation_error).__name__}: {reconciliation_error}"
        )
        return
    if snapshot is None:
        error.add_note(
            "materialization commit outcome is indeterminate because the proposal "
            "snapshot is unknown; exact artifact tree preserved for adoption"
        )
        return
    proposal = snapshot.proposal
    if proposal.state is ProposalState.PROPOSED:
        error.add_note(
            "materialization reconciliation observed PROPOSED, but a read snapshot "
            "is not cleanup authority; exact artifact tree preserved for adoption"
        )
        return
    if (
        proposal.state is ProposalState.MATERIALIZED
        and proposal.materialized_path == path
        and proposal.materialized_digest == digest
    ):
        error.add_note(
            "materialization commit was durably reconciled to the exact path and "
            "digest; exact artifact tree preserved"
        )
        return
    error.add_note(
        "materialization commit outcome is indeterminate because the authoritative "
        f"snapshot is {proposal.state.value} with different ownership; exact "
        "artifact tree preserved for adoption"
    )


def _close_materialization_fd(
    descriptor: int,
    primary_error: BaseException | None,
    label: str,
) -> None:
    """Close one disarmed descriptor without replacing a primary exception."""

    try:
        os.close(descriptor)
    except BaseException as close_error:
        if primary_error is None:
            raise
        primary_error.add_note(
            f"materialization {label} close failed without replacing the original "
            f"exception: {type(close_error).__name__}: {close_error}"
        )


def materialize_proposal(
    store: MbaDiscoveryStore,
    proposal_id: str,
    output_dir: Path,
) -> tuple[str, str]:
    """Atomically render exactly rule and fixture artifacts for one proposal."""

    snapshot = store.proposal_snapshot(proposal_id)
    if snapshot is None:
        raise ValueError("unknown_proposal")
    proposal_row = snapshot.proposal
    proposal = decode_proposal_payload(proposal_row.proposal_payload)
    if proposal.fingerprint != proposal_row.proposal_fingerprint:
        raise ValueError("proposal_payload_identity_mismatch")
    output_dir = Path(os.path.abspath(os.fspath(Path(output_dir).expanduser())))
    _reject_symlink_components(output_dir)
    names = {
        f"{proposal.fingerprint}.rule.py": render_rule_source(proposal),
        f"{proposal.fingerprint}.fixture.json": _fixture_json(proposal.fixture),
    }
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    parent_fd = _open_dir(output_dir.parent)
    expected = {name: value.encode("utf-8") for name, value in names.items()}
    output_name = output_dir.name
    if not output_name:
        os.close(parent_fd)
        raise ValueError("output directory name must be non-empty")
    final_fd: int | None = None
    stage_fd: int | None = None
    stage_path: Path | None = None
    published = False
    committed = False
    cleanup_published = True
    mark_error: BaseException | None = None
    root_identity: tuple[int, int] | None = None
    child_identities: dict[str, tuple[int, int]] = {}
    try:
        try:
            final_fd = _open_at(parent_fd, output_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except FileNotFoundError:
            final_fd = None

        if proposal_row.state is ProposalState.MATERIALIZED:
            if final_fd is None:
                raise ValueError("proposal_not_proposed")
            try:
                info = os.fstat(final_fd)
                digest, _ = _inspect_tree(final_fd, output_dir, expected, fsync_files=False)
            finally:
                closing_final_fd = final_fd
                final_fd = None
                os.close(closing_final_fd)
            if str(output_dir) == proposal_row.materialized_path and digest == proposal_row.materialized_digest:
                return str(output_dir), digest
            raise ValueError("proposal_not_proposed")
        if proposal_row.state is not ProposalState.PROPOSED:
            raise ValueError("proposal_not_proposed")

        if final_fd is not None:
            try:
                info = os.fstat(final_fd)
                root_identity = (info.st_dev, info.st_ino)
                digest, child_identities = _inspect_tree(
                    final_fd, output_dir, expected, fsync_files=True
                )
                os.fsync(final_fd)
                os.fsync(parent_fd)
                _verify_parent_path(output_dir.parent, parent_fd)
            finally:
                closing_final_fd = final_fd
                final_fd = None
                os.close(closing_final_fd)
            receipt = store.mark_materialized(
                proposal_id,
                str(output_dir),
                digest,
                expected_state=proposal_row.state,
                expected_revision=snapshot.group.revision,
                path_commit_guard=lambda: _verify_parent_path(
                    output_dir.parent, parent_fd
                ),
            )
            if receipt.status not in (ReceiptStatus.MATERIALIZED, ReceiptStatus.DUPLICATE):
                raise RuntimeError(receipt.reason or receipt.status.value)
            committed = True
            return str(output_dir), digest

        stage_name = _mkdtemp_at(
            parent_fd, f".{output_name}.{proposal.fingerprint[:12]}."
        )
        stage_path = output_dir.parent / stage_name
        stage_fd = _open_at(
            parent_fd, stage_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        for name, content in expected.items():
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=stage_fd,
            )
            try:
                offset = 0
                while offset < len(content):
                    offset += os.write(descriptor, content[offset:])
                os.fsync(descriptor)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or _read_fd(descriptor) != content:
                    raise OSError(errno.EIO, "staged artifact verification failed")
            finally:
                os.close(descriptor)
        os.fsync(stage_fd)
        digest = _digest_files(expected)
        _exclusive_rename(parent_fd, stage_name, output_name)
        published = True
        try:
            stage_path = None
            closing_stage_fd = stage_fd
            stage_fd = None
            try:
                os.close(closing_stage_fd)
            except BaseException:
                cleanup_published = False
                raise
            final_fd = _open_at(parent_fd, output_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            info = os.fstat(final_fd)
            root_identity = (info.st_dev, info.st_ino)
            inspected_digest, child_identities = _inspect_tree(
                final_fd, output_dir, expected, fsync_files=True
            )
            if inspected_digest != digest:
                raise OSError(errno.EIO, "published artifact digest changed")
            os.fsync(final_fd)
            os.fsync(parent_fd)
            _verify_parent_path(output_dir.parent, parent_fd)
            closing_final_fd = final_fd
            final_fd = None
            try:
                os.close(closing_final_fd)
            except BaseException:
                cleanup_published = False
                raise
        except BaseException as error:
            mark_error = error
            raise
        cleanup_published = False
        try:
            receipt = store.mark_materialized(
                proposal_id,
                str(output_dir),
                digest,
                expected_state=proposal_row.state,
                expected_revision=snapshot.group.revision,
                path_commit_guard=lambda: _verify_parent_path(
                    output_dir.parent, parent_fd
                ),
            )
        except BaseException as error:
            mark_error = error
            _reconcile_materialization_error(
                store, proposal_id, str(output_dir), digest, error
            )
            raise
        if receipt.status not in (ReceiptStatus.MATERIALIZED, ReceiptStatus.DUPLICATE):
            mark_error = RuntimeError(receipt.reason or receipt.status.value)
            raise mark_error
        committed = True
        return str(output_dir), digest
    finally:
        if final_fd is not None:
            closing_final_fd = final_fd
            final_fd = None
            _close_materialization_fd(
                closing_final_fd, mark_error, "published-tree descriptor"
            )
        if stage_fd is not None:
            closing_stage_fd = stage_fd
            stage_fd = None
            _close_materialization_fd(
                closing_stage_fd, mark_error, "staging-tree descriptor"
            )
        if stage_path is not None:
            _remove_private_tree(parent_fd, output_dir.parent, stage_path.name)
        if (
            published
            and not committed
            and cleanup_published
            and root_identity is not None
        ):
            try:
                _quarantine_owned_tree(
                    parent_fd,
                    output_dir.parent,
                    output_name,
                    expected,
                    root_identity,
                    child_identities,
                )
            except BaseException as cleanup_error:
                if mark_error is None:
                    raise
                mark_error.add_note(
                    "materialization cleanup failed without replacing the original "
                    "exception; artifact tree preserved: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        closing_parent_fd = parent_fd
        parent_fd = -1
        _close_materialization_fd(
            closing_parent_fd, mark_error, "parent descriptor"
        )


__all__ = [
    "DiscoveryMiner",
    "MineOutcome",
    "_tree_digest",
    "budget_fingerprint",
    "materialize_proposal",
]

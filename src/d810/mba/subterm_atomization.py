"""Deterministic representation-only atomization for repeated MBA subterms."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from d810.mba.typed_term import TypedBvTerm, term_cost, term_fingerprint


_ATOM_NAMESPACE = "d810.mba.atom.v1"


def _is_reserved_namespace(leaf_key: object) -> bool:
    return (
        isinstance(leaf_key, tuple)
        and bool(leaf_key)
        and leaf_key[0] == _ATOM_NAMESPACE
    )


def _validate_atom_key(leaf_key: object) -> tuple[object, ...]:
    if not isinstance(leaf_key, tuple) or len(leaf_key) != 3:
        raise ValueError("reserved atom key is malformed")
    if leaf_key[0] != _ATOM_NAMESPACE:
        raise ValueError("atom key is outside the reserved namespace")
    if type(leaf_key[1]) is not int or leaf_key[1] < 0:
        raise ValueError("reserved atom ordinal is malformed")
    if type(leaf_key[2]) is not str or not leaf_key[2]:
        raise ValueError("reserved atom fingerprint is malformed")
    return leaf_key


def _walk(term: TypedBvTerm):
    yield term
    for child in term.children:
        yield from _walk(child)


def _validate_term(term: object, *, label: str) -> TypedBvTerm:
    if not isinstance(term, TypedBvTerm):
        raise TypeError(f"{label} must be a TypedBvTerm")
    for node in _walk(term):
        if node.operation is None and node.leaf_key is not None:
            if _is_reserved_namespace(node.leaf_key):
                _validate_atom_key(node.leaf_key)
    return term


def _replace_subterm(
    term: TypedBvTerm,
    target_fingerprint: str,
    target: TypedBvTerm,
    replacement: TypedBvTerm,
    *,
    replace_root: bool,
) -> TypedBvTerm:
    """Rebuild a term, replacing matching immutable operator subtrees."""

    if replace_root and term_fingerprint(term) == target_fingerprint:
        if term != target:
            raise ValueError("term fingerprint collision during atomization")
        return replacement

    if term.operation is None:
        return term
    children = tuple(
        _replace_subterm(
            child,
            target_fingerprint,
            target,
            replacement,
            replace_root=True,
        )
        for child in term.children
    )
    if children == term.children:
        return term
    return TypedBvTerm(
        operation=term.operation,
        width=term.width,
        children=children,
        shift_count=term.shift_count,
    )


def _count_operator_subterms(
    term: TypedBvTerm,
) -> tuple[dict[str, int], dict[str, TypedBvTerm]]:
    counts: Counter[str] = Counter()
    representatives: dict[str, TypedBvTerm] = {}

    def visit(node: TypedBvTerm, *, is_root: bool = False) -> None:
        if node.operation is not None and not is_root:
            fingerprint = term_fingerprint(node)
            representative = representatives.get(fingerprint)
            if representative is not None and representative != node:
                raise ValueError("term fingerprint collision in subterm atomization")
            representatives.setdefault(fingerprint, node)
            counts[fingerprint] += 1
        for child in node.children:
            visit(child)

    visit(term, is_root=True)
    return dict(counts), representatives


@dataclass(frozen=True, slots=True)
class MbaAtomBinding:
    leaf_key: tuple[object, ...]
    original_subterm: TypedBvTerm
    occurrence_count: int
    saved_operator_nodes: int

    def __post_init__(self) -> None:
        _validate_atom_key(self.leaf_key)
        original = _validate_term(self.original_subterm, label="original_subterm")
        if original.operation is None:
            raise ValueError("atom binding must describe an operator subterm")
        if self.leaf_key[2] != term_fingerprint(original):
            raise ValueError("atom key fingerprint does not match original_subterm")
        if type(self.occurrence_count) is not int or self.occurrence_count < 2:
            raise ValueError("atom occurrence_count must be at least two")
        if type(self.saved_operator_nodes) is not int or self.saved_operator_nodes <= 0:
            raise ValueError("atom saved_operator_nodes must be positive")
        expected_savings = (self.occurrence_count - 1) * term_cost(original)[0]
        if self.saved_operator_nodes != expected_savings:
            raise ValueError("atom saved_operator_nodes is inconsistent")


@dataclass(frozen=True, slots=True)
class AtomizedMbaTerm:
    original_term: TypedBvTerm
    atomized_term: TypedBvTerm
    bindings: tuple[MbaAtomBinding, ...]

    def __post_init__(self) -> None:
        self._validate_contract()

    def _validate_contract(self) -> None:
        """Validate the complete public view contract, including replay."""

        original = _validate_term(self.original_term, label="original_term")
        atomized = _validate_term(self.atomized_term, label="atomized_term")
        if original.width != atomized.width:
            raise ValueError("original and atomized terms must have the same width")
        if any(
            node.operation is None
            and node.leaf_key is not None
            and _is_reserved_namespace(node.leaf_key)
            for node in _walk(original)
        ):
            raise ValueError("original term contains a reserved atom namespace")
        bindings = self.bindings
        if type(bindings) is not tuple:
            raise TypeError("bindings must be a canonical tuple")
        if any(not isinstance(binding, MbaAtomBinding) for binding in bindings):
            raise TypeError("bindings must contain MbaAtomBinding values")
        keys = [binding.leaf_key for binding in bindings]
        if len(keys) != len(set(keys)):
            raise ValueError("atom bindings contain duplicate keys")
        for binding in bindings:
            if binding.original_subterm.width != original.width:
                raise ValueError("atom binding width does not match the term")

        known = {binding.leaf_key: binding for binding in bindings}
        for node in _walk(atomized):
            if node.operation is None and node.leaf_key is not None:
                if not _is_reserved_namespace(node.leaf_key):
                    continue
                key = _validate_atom_key(node.leaf_key)
                binding = known.get(key)
                if binding is None:
                    raise ValueError("atomized term contains an unknown reserved atom")
                if node.width != binding.original_subterm.width:
                    raise ValueError("reserved atom width does not match its binding")
        current = self.original_term
        prior_bindings: dict[tuple[object, ...], MbaAtomBinding] = {}
        for ordinal, binding in enumerate(self.bindings):
            key = _validate_atom_key(binding.leaf_key)
            if key[1] != ordinal:
                raise ValueError("atom binding ordinals must match sequence order")
            expected_fingerprint = term_fingerprint(binding.original_subterm)
            if key[2] != expected_fingerprint:
                raise ValueError("atom binding fingerprint does not match provenance")
            for node in _walk(binding.original_subterm):
                if node.operation is None and node.leaf_key is not None:
                    if not _is_reserved_namespace(node.leaf_key):
                        continue
                    dependency = _validate_atom_key(node.leaf_key)
                    if dependency not in prior_bindings:
                        if dependency[1] >= ordinal:
                            raise ValueError("atom binding has a forward dependency")
                        raise ValueError("atom binding has an unknown dependency")

            counts, representatives = _count_operator_subterms(current)
            actual_count = counts.get(expected_fingerprint, 0)
            representative = representatives.get(expected_fingerprint)
            if representative is None or representative != binding.original_subterm:
                raise ValueError("atom binding cannot be replayed from original_term")
            if actual_count != binding.occurrence_count:
                raise ValueError("atom binding occurrence_count does not match replay")
            atom = TypedBvTerm(None, current.width, leaf_key=key)
            current = _replace_subterm(
                current,
                expected_fingerprint,
                binding.original_subterm,
                atom,
                replace_root=False,
            )
            prior_bindings[key] = binding

        if current != self.atomized_term:
            raise ValueError("atomized_term does not derive from original_term")

    def restore(self, replacement: TypedBvTerm) -> TypedBvTerm:
        """Restore synthetic atoms in a provider replacement in reverse order."""

        replacement = _validate_term(replacement, label="replacement")
        if replacement.width != self.original_term.width:
            raise ValueError("replacement width does not match the atomized term")
        known = {binding.leaf_key: binding for binding in self.bindings}
        for node in _walk(replacement):
            if node.operation is None and node.leaf_key is not None:
                if not _is_reserved_namespace(node.leaf_key):
                    continue
                key = _validate_atom_key(node.leaf_key)
                binding = known.get(key)
                if binding is None:
                    raise ValueError("replacement contains an unknown reserved atom")
                if node.width != binding.original_subterm.width:
                    raise ValueError("replacement atom width does not match its binding")

        restored = replacement
        for binding in reversed(self.bindings):
            restored = _replace_leaf(restored, binding.leaf_key, binding.original_subterm)
        for node in _walk(restored):
            if node.operation is None and node.leaf_key is not None and _is_reserved_namespace(
                node.leaf_key
            ):
                raise ValueError("restoration left a reserved atom unresolved")
        return restored


def _replace_leaf(
    term: TypedBvTerm,
    target_key: tuple[object, ...],
    replacement: TypedBvTerm,
) -> TypedBvTerm:
    if term.operation is None:
        if term.leaf_key == target_key:
            if term.width != replacement.width:
                raise ValueError("atom replacement width does not match")
            return replacement
        return term
    children = tuple(_replace_leaf(child, target_key, replacement) for child in term.children)
    if children == term.children:
        return term
    return TypedBvTerm(
        operation=term.operation,
        width=term.width,
        children=children,
        shift_count=term.shift_count,
    )


def atomize_repeated_subterms(
    term: TypedBvTerm,
    *,
    min_occurrences: int = 2,
    min_operator_nodes: int = 1,
    max_atoms: int = 4,
) -> AtomizedMbaTerm:
    """Replace repeated operator subtrees with deterministic synthetic leaves."""

    if type(min_occurrences) is not int or min_occurrences < 2:
        raise ValueError("min_occurrences must be an integer at least two")
    if type(min_operator_nodes) is not int or min_operator_nodes < 1:
        raise ValueError("min_operator_nodes must be an integer at least one")
    if type(max_atoms) is not int or max_atoms < 0:
        raise ValueError("max_atoms must be a non-negative integer")

    term = _validate_term(term, label="term")
    if any(
        node.operation is None
        and node.leaf_key is not None
        and _is_reserved_namespace(node.leaf_key)
        for node in _walk(term)
    ):
        raise ValueError("term contains a reserved atom namespace collision")

    current = term
    bindings: list[MbaAtomBinding] = []
    while len(bindings) < max_atoms:
        counts, representatives = _count_operator_subterms(current)
        eligible = []
        for fingerprint, occurrences in counts.items():
            representative = representatives[fingerprint]
            operator_nodes = term_cost(representative)[0]
            if occurrences < min_occurrences or operator_nodes < min_operator_nodes:
                continue
            saved = (occurrences - 1) * operator_nodes
            eligible.append(
                (
                    -saved,
                    -occurrences,
                    -operator_nodes,
                    fingerprint,
                    representative,
                    occurrences,
                    saved,
                )
            )
        if not eligible:
            break
        (
            _saved_sort,
            _occurrences_sort,
            _operators_sort,
            fingerprint,
            representative,
            occurrences,
            saved,
        ) = min(eligible)
        leaf_key = (_ATOM_NAMESPACE, len(bindings), fingerprint)
        atom = TypedBvTerm(None, current.width, leaf_key=leaf_key)
        current = _replace_subterm(
            current,
            fingerprint,
            representative,
            atom,
            replace_root=False,
        )
        bindings.append(
            MbaAtomBinding(
                leaf_key=leaf_key,
                original_subterm=representative,
                occurrence_count=occurrences,
                saved_operator_nodes=saved,
            )
        )

    return AtomizedMbaTerm(term, current, tuple(bindings))


__all__ = [
    "AtomizedMbaTerm",
    "MbaAtomBinding",
    "atomize_repeated_subterms",
]

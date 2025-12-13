"""Merkle tree utilities for micro‑code diffing.

This module defines simple classes to build a Merkle tree from a list of
leaf hashes and to compute differences between two trees.  A Merkle tree
is a binary tree in which each non‑leaf node stores the hash of its two
children concatenated.  The root hash represents the entire collection
and can be used to detect changes.  When comparing two trees, leaf
indices whose hashes differ represent the modified elements.

This implementation does not depend on IDA and can be used in unit
tests to verify Merkle diff behaviour.  Real usage within the
unflattening pipeline would compute block hashes for each micro‑code
block and build a Merkle tree per function.  The tree structure can
then be stored persistently to avoid reprocessing unchanged blocks.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional


def _sha256_concat(left: str, right: str) -> str:
    """Hash the concatenation of two hex digests and return a new hex digest."""
    return hashlib.sha256((left + right).encode("utf-8")).hexdigest()


@dataclass
class MerkleTree:
    """A simple Merkle tree built from a list of leaf hashes."""

    leaves: List[str]
    levels: List[List[str]]

    def __init__(self, leaves: List[str]) -> None:
        if not leaves:
            raise ValueError("Cannot build a Merkle tree with no leaves")
        # Copy the leaf list to avoid external mutation
        self.leaves = list(leaves)
        # Build levels from leaves up to the root
        self.levels = [self.leaves]
        current_level = self.leaves
        while len(current_level) > 1:
            next_level: List[str] = []
            # Iterate over pairs; if odd number of nodes, duplicate last
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                parent = _sha256_concat(left, right)
                next_level.append(parent)
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        """Return the root hash of the Merkle tree."""
        return self.levels[-1][0]

    def diff(self, other: "MerkleTree") -> List[int]:
        """Return indices of leaves that differ between this tree and another.

        The two trees must have the same number of leaves.  Differences are
        determined by comparing corresponding leaf hashes.

        Parameters
        ----------
        other : MerkleTree
            The other Merkle tree to compare against.

        Returns
        -------
        list[int]
            A list of indices of leaves where the two trees differ.
        """
        if len(self.leaves) != len(other.leaves):
            raise ValueError("Cannot diff Merkle trees with different number of leaves")
        differing_indices: List[int] = []
        for idx, (h1, h2) in enumerate(zip(self.leaves, other.leaves)):
            if h1 != h2:
                differing_indices.append(idx)
        return differing_indices

    def to_dict(self) -> dict:
        """Serialise the Merkle tree to a JSON‑serialisable dictionary."""
        return {"leaves": self.leaves, "levels": self.levels}

    @classmethod
    def from_dict(cls, data: dict) -> "MerkleTree":
        """Reconstruct a Merkle tree from a dictionary returned by :meth:`to_dict`."""
        tree = cls(data["leaves"])
        # Overwrite computed levels with stored levels in case they differ
        tree.levels = data["levels"]
        return tree
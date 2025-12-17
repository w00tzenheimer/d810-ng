"""Unit tests for the Merkle tree utilities."""

from d810.core.merkle import MerkleTree


def test_build_root():
    leaves = ["a", "b", "c", "d"]
    tree = MerkleTree(leaves)
    # Root hash should be non-empty and deterministic
    assert isinstance(tree.root, str)
    assert tree.leaves == leaves
    # Building the same tree again should yield the same root
    tree2 = MerkleTree(leaves)
    assert tree.root == tree2.root


def test_diff():
    tree1 = MerkleTree(["h1", "h2", "h3", "h4"])
    tree2 = MerkleTree(["h1", "hX", "h3", "h4"])
    diff = tree1.diff(tree2)
    assert diff == [1]

"""Hex‑Rays ctree snapshotting helpers.

Unflattening dispatchers and applying binary patches can simplify the
decompiler’s output significantly.  To avoid running the unflattening
analysis and the decompiler repeatedly on subsequent sessions, this
module provides helpers to serialise and deserialise the final ctree
(C code representation) of a function.  The snapshot can be stored in
the persistent cache keyed by the function hash and restored when the
same function is encountered again.

These helpers are intentionally lightweight; they do not depend on IDA
and simply operate on whatever object the caller provides.  When
running inside IDA, ``cfunc_t`` objects expose APIs to traverse the
ctree; here we fall back to serialising the object's `repr` and any
additional attributes that are JSON serialisable.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional


def serialize_ctree(ctree: Any) -> Dict[str, Any]:
    """Serialise a ctree object into a JSON‑serialisable dictionary.

    In a real IDA environment, this function should traverse the
    ``cinsn_t`` nodes and record the structure of the ctree.  In this
    implementation we fall back to storing the string representation
    of the ctree along with any primitive attributes that may exist.

    Parameters
    ----------
    ctree : Any
        The ctree object (e.g. ``cfunc_t``) to serialise.

    Returns
    -------
    dict
        A dictionary that can be written to JSON.
    """
    data: Dict[str, Any] = {"repr": repr(ctree)}
    # Attempt to extract simple attributes from the ctree
    for attr in ("ea", "name", "maturity"):
        if hasattr(ctree, attr):
            try:
                val = getattr(ctree, attr)
                # Only store JSON‑serialisable values
                json.dumps(val)
                data[attr] = val
            except Exception:
                pass
    return data


def deserialize_ctree(data: Dict[str, Any]) -> Any:
    """Deserialize a ctree snapshot back into a Python object.

    Without the Hex‑Rays SDK, this function simply returns the stored
    representation string.  In a real environment, one could recreate
    a ``cfunc_t`` or use the IDA decompiler API to inject the snapshot
    back into the decompiler.
    """
    return data.get("repr")


def save_ctree_snapshot(func_hash: str, ctree: Any, cache) -> None:
    """Serialise and store a ctree snapshot in the given cache."""
    snapshot = serialize_ctree(ctree)
    cache.set(f"ctree::{func_hash}", snapshot)


def load_ctree_snapshot(func_hash: str, cache) -> Optional[Dict[str, Any]]:
    """Load a ctree snapshot from the cache for the given function hash."""
    return cache.get(f"ctree::{func_hash}")
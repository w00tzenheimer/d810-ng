"""Throwaway pytest plugin: content-ID construction -> consumption census.

Ticket d81-ug2e (epic d81-5j8r), Phase 1.  MEASUREMENT ONLY -- nothing here is
production code and nothing it patches is committed.

Mechanism (deliberately NOT a ``str`` subclass: this package is full of exact
``type(x) is str`` validators, and a ``TrackedId`` would be rejected by them --
see model.py:5944 / model.py:6525 / views.py:364 / runtime_authority.py:229):

1. Wrap the mint entry points (``ids.content_id``, ``ids._record_content_id``,
   ``cfg_transaction._cfg_content_id``) and rebind them across every module
   that did ``from .ids import content_id``.  Each mint gets a serial, its
   caller, and a push/pop on a mint stack, so a read that happens *inside*
   a mint knows which parent mint demanded it.
2. Replace the ``member_descriptor`` of every field of every frozen
   ``slots=True`` authority dataclass with a tracking data descriptor.
   ``__get__`` records the reader's frame (file, function, line, and the two
   bytecode ops that follow the read -- which is what distinguishes a
   ``COMPARE_OP`` from a ``LOAD_ATTR`` that just feeds an encoder).
   ``__set__`` records the writer's frame; because every one of these classes
   is ``frozen=True``, the only way to reach ``__set__`` is
   ``object.__setattr__`` -- so this IS the ``object.__setattr__`` census.
3. ``ids.record_content_id_mint`` is counted separately so the harness total
   can be reconciled against the production ``content_id_mints`` counter.
"""

from __future__ import annotations

import atexit
import dis
import json
import os
import sys
import traceback

_OUT = os.environ.get("D810_IDCENSUS_OUT", "/work/.tmp/idcensus/census.json")

_IDENT_SUFFIXES = ("_id", "_digest", "_fingerprint", "_commitment", "_ids", "_seal")

# ---------------------------------------------------------------- tables ---
_caller_index: dict[tuple, int] = {}
_callers: list[tuple] = []

_mints: list[dict] = []
_mint_stack: list[int] = []
_mint_calls = [0]          # wrapper invocations (incl. cache hits)
_raw_mint_events = [0]     # ids.record_content_id_mint() calls

_value_index: dict[str, int] = {}
_values: list[str] = []

# value index -> {caller index: count}
_value_reads: dict[int, dict[int, int]] = {}
# value index -> {parent mint serial: count}  (reads taken by encoder frames)
_value_edges: dict[int, dict[int, int]] = {}
# reads of sha256-shaped strings never minted through our wrappers
_unknown_reads: dict[int, int] = {}
# (caller index, type name, field, phase) -> count
_writes: dict[tuple, int] = {}

_ident_field: dict[str, str] = {}     # record type name -> its omitted identity field
_published: dict[int, str] = {}       # id(record) -> type name, once its ID was minted
_errors: list[str] = []
_installed = [False]
_descriptors_installed = [False]
_wrapped_classes: list[str] = []
_UNMINTED = "sha256:" + "0" * 64

_ENCODER_FUNCS = frozenset({
    "_wire", "_external_wire", "_json_bytes", "_record_content_id",
    "_semantic_safety_case_projection", "canonical_field_value",
    "canonical_bytes", "_occurrence_stamp", "_occurrence_walk",
    "is_immutable_closure", "_immutable_closure", "occurrence_ids",
    "_seal_preconditions_hold", "decide_seal", "_stage", "stage",
    "content_id", "_content_id_digest", "authority_id",
})


def _vidx(value: str) -> int:
    idx = _value_index.get(value)
    if idx is None:
        idx = len(_values)
        _value_index[value] = idx
        _values.append(value)
    return idx


# ------------------------------------------------------- caller identity ---
_succ_cache: dict[int, tuple[object, dict[int, str]]] = {}


def _succ_map(code) -> dict[int, str]:
    entry = _succ_cache.get(id(code))
    if entry is not None and entry[0] is code:
        return entry[1]
    table: dict[int, str] = {}
    try:
        ins = [i for i in dis.get_instructions(code) if i.opname != "CACHE"]
        for pos, item in enumerate(ins):
            table[item.offset] = ",".join(
                x.opname for x in ins[pos + 1: pos + 4]
            )
    except Exception:  # pragma: no cover - defensive
        table = {}
    _succ_cache[id(code)] = (code, table)
    return table


def _ckey(frame) -> int:
    code = frame.f_code
    key = (
        code.co_filename,
        code.co_name,
        frame.f_lineno,
        _succ_map(code).get(frame.f_lasti, ""),
    )
    idx = _caller_index.get(key)
    if idx is None:
        idx = len(_callers)
        _caller_index[key] = idx
        _callers.append(key)
    return idx


def _cstack(depth: int = 8) -> list[int]:
    """Record the caller chain above a mint, innermost first.

    Phase 2 (d81-cxzv) needs to answer *who demanded this ID*, and the single
    immediate caller is always the ``ids`` wrapper.  Eight frames is enough to
    reach the producer through a factory and a dataclass ``__init__``.
    """

    out: list[int] = []
    frame = sys._getframe(2)
    while frame is not None and len(out) < depth:
        out.append(_ckey(frame))
        frame = frame.f_back
    return out


def _is_encoder(idx: int) -> bool:
    key = _callers[idx]
    return key[1] in _ENCODER_FUNCS


# --------------------------------------------------------- read / write ----
def _record_read(value, frame) -> None:
    if len(value) != 71 or not value.startswith("sha256:"):
        return
    vi = _value_index.get(value)
    ci = _ckey(frame)
    if vi is None:
        _unknown_reads[ci] = _unknown_reads.get(ci, 0) + 1
        return
    bucket = _value_reads.get(vi)
    if bucket is None:
        bucket = _value_reads[vi] = {}
    bucket[ci] = bucket.get(ci, 0) + 1
    if _mint_stack and _is_encoder(ci):
        edges = _value_edges.get(vi)
        if edges is None:
            edges = _value_edges[vi] = {}
        parent = _mint_stack[-1]
        edges[parent] = edges.get(parent, 0) + 1


def _write_phase(inst, cls_name: str) -> str:
    ident = _ident_field.get(cls_name)
    if ident is not None:
        desc = type(inst).__dict__.get(ident)
        cur = None
        if isinstance(desc, _TrackedField):
            try:
                cur = desc.orig.__get__(inst, type(inst))
            except AttributeError:
                cur = None
        if cur is None:
            return "CONSTRUCTION_TIME"
        if type(cur) is str and len(cur) == 71 and cur.startswith("sha256:"):
            return "CONSTRUCTION_TIME" if cur == _UNMINTED else "POST_PUBLICATION"
        return "CONSTRUCTION_TIME"
    if _published.get(id(inst)) == cls_name:
        return "POST_PUBLICATION"
    return "CONSTRUCTION_TIME_NO_IDENTITY"


class _TrackedField:
    __slots__ = ("orig", "name", "cls_name", "track_read")

    def __init__(self, orig, name, cls_name, track_read):
        self.orig = orig
        self.name = name
        self.cls_name = cls_name
        self.track_read = track_read

    def __get__(self, inst, owner=None):
        if inst is None:
            return self
        value = self.orig.__get__(inst, owner)
        if self.track_read and type(value) is str:
            _record_read(value, sys._getframe(1))
        return value

    def __set__(self, inst, value):
        try:
            phase = _write_phase(inst, self.cls_name)
            key = (_ckey(sys._getframe(1)), self.cls_name, self.name, phase)
            _writes[key] = _writes.get(key, 0) + 1
        except Exception as exc:  # pragma: no cover
            _errors.append("write-track: %r" % (exc,))
        self.orig.__set__(inst, value)

    def __delete__(self, inst):
        self.orig.__delete__(inst)


# ------------------------------------------------------------ installers ---
def _rebind(module_attr_name: str, original, replacement) -> int:
    """Rebind ``original`` -> ``replacement`` in every module that imported it."""
    count = 0
    for module in list(sys.modules.values()):
        if module is None:
            continue
        try:
            ns = module.__dict__
        except Exception:
            continue
        for key, value in list(ns.items()):
            if value is original:
                ns[key] = replacement
                count += 1
    return count


def _wrap_content_id(orig):
    def content_id(schema, value):
        _mint_calls[0] += 1
        serial = len(_mints)
        rec = {
            "serial": serial,
            "kind": "content_id",
            "stack": _cstack(),
            "schema": schema,
            "type": type(value).__name__,
            "caller": _ckey(sys._getframe(1)),
            "parent": _mint_stack[-1] if _mint_stack else -1,
            "depth": len(_mint_stack),
        }
        _mints.append(rec)
        _mint_stack.append(serial)
        before = _raw_mint_events[0]
        try:
            out = orig(schema, value)
        finally:
            _mint_stack.pop()
        rec["value"] = _vidx(out)
        rec["mint_events"] = _raw_mint_events[0] - before
        _published[id(value)] = rec["type"]
        return out

    return content_id


def _wrap_record_content_id(orig):
    def _record_content_id(schema, value, omitted_field):
        _mint_calls[0] += 1
        serial = len(_mints)
        type_name = type(value).__name__
        _ident_field.setdefault(type_name, omitted_field)
        rec = {
            "serial": serial,
            "kind": "_record_content_id",
            "stack": _cstack(),
            "schema": schema,
            "type": type_name,
            "omitted": omitted_field,
            "caller": _ckey(sys._getframe(1)),
            "parent": _mint_stack[-1] if _mint_stack else -1,
            "depth": len(_mint_stack),
        }
        _mints.append(rec)
        _mint_stack.append(serial)
        before = _raw_mint_events[0]
        try:
            out = orig(schema, value, omitted_field)
        finally:
            _mint_stack.pop()
        rec["value"] = _vidx(out)
        rec["mint_events"] = _raw_mint_events[0] - before
        _published[id(value)] = type_name
        return out

    return _record_content_id


def _wrap_cfg_content_id(orig):
    def _cfg_content_id(domain, fields):
        _mint_calls[0] += 1
        serial = len(_mints)
        rec = {
            "serial": serial,
            "kind": "_cfg_content_id",
            "stack": _cstack(),
            "schema": domain,
            "type": "cfg",
            "caller": _ckey(sys._getframe(1)),
            "parent": _mint_stack[-1] if _mint_stack else -1,
            "depth": len(_mint_stack),
        }
        _mints.append(rec)
        _mint_stack.append(serial)
        try:
            out = orig(domain, fields)
        finally:
            _mint_stack.pop()
        rec["value"] = _vidx(out)
        rec["mint_events"] = 1
        return out

    return _cfg_content_id


#: Second identity family: every production site that manufactures a
#: ``sha256:``-prefixed identity string OUTSIDE ``ids.content_id``.  Found with
#: ``rg 'hexdigest\(\)'`` + ``rg '"sha256:"'`` over src/d810 (tests excluded) and
#: filtered to the ones whose product is 71 chars of ``sha256:<64 hex>`` -- the
#: exact shape the read tracker records.
_FAMILY_SITES = (
    ("d810.backends.hexrays.native_preanalysis_key", "fingerprint_profile_config", "native_key"),
    ("d810.backends.hexrays.input_identity_attestation", "function_fingerprint", "native_key"),
    ("d810.backends.hexrays.input_identity_attestation", "segment_map_digest", "native_key"),
    ("d810.core.input_identity_attestation", "_normalized_digest", "native_key"),
    ("d810.core.input_identity_attestation", "local_idb_identity", "native_key"),
    ("d810.ir.graph_fingerprint", "portable_graph_fingerprint", "graph_fingerprint"),
    ("d810.ir.graph_fingerprint", "portable_graph_fingerprint_values", "graph_fingerprint"),
    ("d810.analyses.control_flow.semantic_route_evidence", "_canonical_route_group_id", "route_evidence"),
    ("d810.analyses.control_flow.semantic_route_evidence", "_canonical_route_proof_id", "route_evidence"),
    ("d810.analyses.control_flow.semantic_route_evidence", "_route_assessment_seal", "route_evidence"),
    ("d810.analyses.control_flow.semantic_route_evidence", "_bound_content_digest", "route_evidence"),
    ("d810.analyses.control_flow.minimal_state_recovery",
     "IntervalHandlerLeafReplayCatalog._topology_epoch", "state_recovery"),
    ("d810.transforms.unflatten_authority.bind", "_retirement_binding_seal", "authority_seal"),
    ("d810.transforms.unflatten_authority.bind", "_terminal_cycle_binding_seal", "authority_seal"),
    ("d810.transforms.unflatten_authority.bind", "_route_content_seal", "authority_seal"),
)
_family_done: set[tuple[str, str]] = set()
_family_report: dict[str, object] = {}


def _wrap_family(orig, label, family):
    def wrapper(*args, **kwargs):
        _mint_calls[0] += 1
        serial = len(_mints)
        rec = {
            "serial": serial,
            "kind": label,
            "family": family,
            "stack": _cstack(),
            "schema": label,
            "type": type(args[0]).__name__ if args else "-",
            "caller": _ckey(sys._getframe(1)),
            "parent": _mint_stack[-1] if _mint_stack else -1,
            "depth": len(_mint_stack),
        }
        _mints.append(rec)
        _mint_stack.append(serial)
        try:
            out = orig(*args, **kwargs)
        finally:
            _mint_stack.pop()
        if type(out) is str and len(out) == 71 and out.startswith("sha256:"):
            rec["value"] = _vidx(out)
        rec["mint_events"] = 1
        return out

    return wrapper


def _install_family() -> None:
    """Wrap the second identity family.  Idempotent; retried per test."""
    for mod_name, attr, family in _FAMILY_SITES:
        key = (mod_name, attr)
        if key in _family_done:
            continue
        module = sys.modules.get(mod_name)
        if module is None:
            continue
        try:
            if "." in attr:
                cls_name, meth = attr.split(".", 1)
                owner = getattr(module, cls_name, None)
                if owner is None:
                    continue
                raw = owner.__dict__.get(meth)
                static = isinstance(raw, staticmethod)
                func = raw.__func__ if static else raw
                if func is None or getattr(func, "_idcensus", False):
                    _family_done.add(key)
                    continue
                new = _wrap_family(func, mod_name.rsplit(".", 1)[-1] + "." + attr, family)
                new._idcensus = True
                setattr(owner, meth, staticmethod(new) if static else new)
            else:
                orig = getattr(module, attr, None)
                if orig is None or getattr(orig, "_idcensus", False):
                    _family_done.add(key)
                    continue
                new = _wrap_family(orig, mod_name.rsplit(".", 1)[-1] + "." + attr, family)
                new._idcensus = True
                _rebind(attr, orig, new)
                setattr(module, attr, new)
            _family_done.add(key)
            _family_report["%s.%s" % (mod_name, attr)] = "wrapped"
        except Exception as exc:  # pragma: no cover
            _errors.append("family %s.%s: %r" % (mod_name, attr, exc))


def _wrap_mint_event(orig):
    def record_content_id_mint():
        _raw_mint_events[0] += 1
        return orig()

    return record_content_id_mint


def _install_descriptors() -> None:
    from d810.transforms.unflatten_authority import ids as _ids

    _ids._ensure_registries()
    classes: dict[int, type] = {}
    for bucket in (_ids._RECORD_TYPES, _ids._EXTERNAL_TYPES):
        for cls in bucket:
            classes[id(cls)] = cls
    for mod_name in (
        "d810.transforms.unflatten_authority.model",
        "d810.transforms.unflatten_authority.bind",
        "d810.transforms.cfg_transaction",
        "d810.transforms.unflatten_authority.views",
        "d810.transforms.unflatten_authority.legacy_codec",
    ):
        module = sys.modules.get(mod_name)
        if module is None:
            continue
        for obj in vars(module).values():
            if isinstance(obj, type) and getattr(obj, "__dataclass_fields__", None):
                classes[id(obj)] = obj
    for cls in classes.values():
        names = getattr(cls, "__slots__", ())
        if isinstance(names, str):
            names = (names,)
        wrapped = 0
        for name in names:
            orig = cls.__dict__.get(name)
            if isinstance(orig, _TrackedField):
                continue
            if type(orig).__name__ != "member_descriptor":
                continue
            track = name.endswith(_IDENT_SUFFIXES)
            try:
                setattr(cls, name, _TrackedField(orig, name, cls.__name__, track))
            except Exception as exc:
                _errors.append("descriptor %s.%s: %r" % (cls.__name__, name, exc))
                continue
            wrapped += 1
        if wrapped:
            _wrapped_classes.append("%s:%d" % (cls.__name__, wrapped))
    _descriptors_installed[0] = True


def _retry_descriptors() -> None:
    """Idempotent re-sweep: classes imported after ``pytest_configure``."""
    try:
        _install_family()
        _install_descriptors()
    except Exception:
        _errors.append("retry_descriptors: " + traceback.format_exc())


def install() -> dict:
    if _installed[0]:
        return {}
    _installed[0] = True
    report: dict[str, object] = {}
    from d810.transforms.unflatten_authority import ids as _ids
    from d810.transforms import cfg_transaction as _cfg

    orig_cid = _ids.content_id
    orig_rcid = _ids._record_content_id
    orig_cfg = _cfg._cfg_content_id
    orig_mint = _ids.record_content_id_mint

    new_cid = _wrap_content_id(orig_cid)
    new_rcid = _wrap_record_content_id(orig_rcid)
    new_cfg = _wrap_cfg_content_id(orig_cfg)
    new_mint = _wrap_mint_event(orig_mint)

    report["rebind_content_id"] = _rebind("content_id", orig_cid, new_cid)
    report["rebind_record_content_id"] = _rebind(
        "_record_content_id", orig_rcid, new_rcid
    )
    report["rebind_cfg_content_id"] = _rebind("_cfg_content_id", orig_cfg, new_cfg)
    report["rebind_mint_event"] = _rebind(
        "record_content_id_mint", orig_mint, new_mint
    )
    try:
        _install_family()
        _install_descriptors()
        report["descriptors"] = len(_wrapped_classes)
    except Exception as exc:
        _errors.append("install_descriptors: %s" % traceback.format_exc())
        report["descriptors_error"] = repr(exc)
    return report


def dump() -> None:
    payload = {
        "values": _values,
        "callers": [list(c) for c in _callers],
        "mints": _mints,
        "value_reads": {
            str(k): {str(ci): n for ci, n in v.items()}
            for k, v in _value_reads.items()
        },
        "value_edges": {
            str(k): {str(p): n for p, n in v.items()}
            for k, v in _value_edges.items()
        },
        "unknown_reads": {str(k): n for k, n in _unknown_reads.items()},
        "writes": [
            {"caller": k[0], "type": k[1], "field": k[2], "phase": k[3], "count": n}
            for k, n in _writes.items()
        ],
        "ident_field": _ident_field,
        "mint_calls": _mint_calls[0],
        "raw_mint_events": _raw_mint_events[0],
        "wrapped_classes": _wrapped_classes,
        "errors": _errors[:200],
        "install": _INSTALL_REPORT,
        "family_wrapped": _family_report,
        "family_missing": [
            "%s.%s" % (m, a) for m, a, _f in _FAMILY_SITES
            if (m, a) not in _family_done
        ],
    }
    os.makedirs(os.path.dirname(_OUT), exist_ok=True)
    tmp = _OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    os.replace(tmp, _OUT)
    sys.stderr.write(
        "d810-idcensus wrote %s mints=%d values=%d callers=%d writes=%d "
        "raw_mint_events=%d errors=%d\n"
        % (
            _OUT, len(_mints), len(_values), len(_callers), len(_writes),
            _raw_mint_events[0], len(_errors),
        )
    )
    sys.stderr.flush()


_INSTALL_REPORT: dict = {}
_dumped = [False]


def _dump_once() -> None:
    if _dumped[0]:
        return
    _dumped[0] = True
    try:
        dump()
    except Exception:
        sys.stderr.write("d810-idcensus dump failed:\n" + traceback.format_exc())


def pytest_configure(config):  # noqa: ARG001
    global _INSTALL_REPORT
    try:
        result = install()
        if result:
            _INSTALL_REPORT = result
    except Exception:
        _errors.append("install: " + traceback.format_exc())
        sys.stderr.write("d810-idcensus install failed:\n" + traceback.format_exc())
    atexit.register(_dump_once)


def pytest_collection_finish(session):  # noqa: ARG001
    if not _installed[0]:
        pytest_configure(None)
    _retry_descriptors()


def pytest_runtest_setup(item):  # noqa: ARG001
    if not _installed[0]:
        pytest_configure(None)
    _retry_descriptors()


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    _retry_descriptors()
    _dump_once()

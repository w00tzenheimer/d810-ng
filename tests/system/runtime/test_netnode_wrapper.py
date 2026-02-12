"""Runtime tests for the IDA9+ netnode wrapper."""

from __future__ import annotations

import os
import platform
import uuid

import pytest

from d810.core.persistence import Netnode


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def _require_ida9_netnode() -> None:
    idaapi = pytest.importorskip("idaapi")
    pytest.importorskip("ida_netnode")

    get_version = getattr(idaapi, "get_kernel_version", None)
    if get_version is None:
        pytest.skip("idaapi.get_kernel_version() is unavailable")

    try:
        major = int(str(get_version()).split(".", 1)[0])
    except Exception:
        pytest.skip("Unable to parse IDA kernel version")

    if major < 9:
        pytest.skip(f"Netnode wrapper test requires IDA9+, found IDA {major}")


@pytest.fixture
def netnode(ida_database) -> Netnode:
    _require_ida9_netnode()
    name = f"$ d810.test.netnode.{uuid.uuid4().hex}"
    node = Netnode(name)
    try:
        yield node
    finally:
        # isolate test data from the user's IDB
        node.kill()


@pytest.mark.usefixtures("configure_hexrays", "setup_libobfuscated_funcs")
class TestNetnodeWrapperRuntime:
    binary_name = _get_default_binary()

    def test_netnode_roundtrip_small_keys(self, netnode: Netnode) -> None:
        payload_int = {"kind": "small-int", "value": 7}
        payload_str = {"kind": "small-str", "value": "hello"}

        netnode[1] = payload_int
        netnode["k1"] = payload_str

        assert netnode[1] == payload_int
        assert netnode["k1"] == payload_str
        assert 1 in netnode
        assert "k1" in netnode

    def test_netnode_roundtrip_large_blob_values(self, netnode: Netnode) -> None:
        large_payload = {"blob": "A" * 6000, "n": 42}

        netnode[2] = large_payload
        netnode["big"] = large_payload

        assert netnode[2] == large_payload
        assert netnode["big"] == large_payload

    def test_netnode_delete_and_get_default(self, netnode: Netnode) -> None:
        netnode[3] = {"x": 1}
        assert 3 in netnode
        del netnode[3]

        assert 3 not in netnode
        assert netnode.get(3, "missing") == "missing"
        with pytest.raises(KeyError):
            _ = netnode[3]

    def test_netnode_iterkeys_contains_written_keys(self, netnode: Netnode) -> None:
        netnode[10] = {"v": "ten"}
        netnode["s10"] = {"v": "str-ten"}

        keys = set(netnode.iterkeys())
        assert 10 in keys
        assert "s10" in keys

    def test_netnode_rejects_none_value(self, netnode: Netnode) -> None:
        with pytest.raises(ValueError, match="must not be None"):
            netnode["none"] = None

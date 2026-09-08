"""Alias coordinates are copied once and public claim/fact checks survive export."""

import pytest

from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityArenaError, RuntimeAuthorityScope
from d810.transforms.unflatten_authority import inventory_publication
from tests.unit.transforms.unflatten_authority.test_bind import _c_local_alias_fixture


def test_alias_coordinate_publication_detaches_and_rejects_claim_drift():
    fixture = _c_local_alias_fixture()
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-projected"))
    claim, fact = fixture["claim"], fixture["patch_step_fact"]
    published = inventory_publication.publish_local_alias_inputs(source, projected, claim, fact)
    assert published.inputs.alias_token == claim.alias_token
    object.__setattr__(claim, "alias_token", "foreign")
    assert published.inputs.alias_token == "alias"
    with pytest.raises(ValueError, match="claim.*changed"):
        inventory_publication.require_local_alias_inputs_export(source, projected, published, claim, fact)


def test_alias_coordinate_publication_preserves_patch_correspondence():
    fixture = _c_local_alias_fixture()
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-projected"))
    claim, fact = fixture["claim"], fixture["patch_step_fact"]
    object.__setattr__(fact, "step_digest", "foreign")
    with pytest.raises(ValueError, match="patch step"):
        inventory_publication.publish_local_alias_inputs(source, projected, claim, fact)


def test_alias_coordinate_publication_refuses_foreign_identity_before_callback():
    fixture = _c_local_alias_fixture()
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-projected"))
    claim, fact = fixture["claim"], fixture["patch_step_fact"]
    owner = claim.owner_subject.block_ref
    native_key = owner.identity.native_key
    calls = []

    class ForeignIdentity:
        @property
        def native_key(self):
            calls.append("native-key")
            return native_key

    object.__setattr__(owner, "identity", ForeignIdentity())
    with pytest.raises(TypeError):
        inventory_publication.publish_local_alias_inputs(source, projected, claim, fact)
    assert calls == []


@pytest.mark.parametrize("mode", ["source-close", "projected-close", "fact-drift", "owner-drift", "foreign-source"])
def test_alias_coordinate_export_preserves_lifetime_and_public_checks(mode):
    fixture = _c_local_alias_fixture()
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-projected"))
    claim, fact = fixture["claim"], fixture["patch_step_fact"]
    publication = inventory_publication.publish_local_alias_inputs(source, projected, claim, fact)
    if mode == "source-close":
        source.close()
    elif mode == "projected-close":
        projected.close()
    elif mode == "fact-drift":
        object.__setattr__(fact, "host_opcode", fact.host_opcode + 1)
    elif mode == "owner-drift":
        owner = claim.owner_subject.block_ref
        object.__setattr__(owner.identity, "exact_instruction_eas", frozenset())
    else:
        source = RuntimeAuthorityArena(RuntimeAuthorityScope("foreign-source"))
    with pytest.raises((TypeError, ValueError, RuntimeAuthorityArenaError)):
        inventory_publication.require_local_alias_inputs_export(source, projected, publication, claim, fact)


def test_alias_publication_rejects_transient_projected_owner_capture_drift(monkeypatch):
    fixture = _c_local_alias_fixture()
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("alias-projected"))
    claim, fact = fixture["claim"], fixture["patch_step_fact"]
    owner = claim.owner_subject.block_ref
    original = owner.identity.exact_instruction_eas
    capture = inventory_publication.inventory_inputs.capture_inventory_reference

    def transient(table, value):
        if table is projected.structural:
            object.__setattr__(owner.identity, "exact_instruction_eas", frozenset())
            try:
                return capture(table, value)
            finally:
                object.__setattr__(owner.identity, "exact_instruction_eas", original)
        return capture(table, value)

    monkeypatch.setattr(inventory_publication.inventory_inputs, "capture_inventory_reference", transient)
    with pytest.raises(ValueError, match="owner.*differ"):
        inventory_publication.publish_local_alias_inputs(source, projected, claim, fact)

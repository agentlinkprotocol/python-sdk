import pytest

from agentlinkprotocol import AgentKey, VaultKey, decrypt_snapshot, encrypt_snapshot, make_ack, open_sealed, seal, sign_fetch


def test_seal_open():
    alice, bob = AgentKey.generate(), AgentKey.generate()
    sealed = seal(bob.public_key, b"see you at 10")
    assert open_sealed(bob, sealed) == b"see you at 10"
    with pytest.raises(Exception):
        open_sealed(alice, sealed)


def test_vault_roundtrip():
    a, k = AgentKey.generate(), VaultKey.generate()
    data = b"memory" * 100
    enc = encrypt_snapshot(k, a.agent_id, 3, data)
    assert decrypt_snapshot(k, a.agent_id, 3, enc) == data
    with pytest.raises(Exception):
        decrypt_snapshot(k, a.agent_id, 4, enc)


def test_ack_and_fetch():
    a = AgentKey.generate()
    assert len(sign_fetch(a, 5)) == 128
    ack = make_ack(a, ["ab" * 16], 1000)
    assert ack["agent_id"] == a.agent_id and len(ack["sig"]) == 128

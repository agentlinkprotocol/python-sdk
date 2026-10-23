import json
from pathlib import Path

from agentlinkprotocol import (
    DOMAIN, AgentKey, card_agent_signing_hash, card_cbor, card_node_signing_hash, card_unsigned_bytes, encode, ephemeral_cbor,
    ephemeral_unsigned, operator_cert_cbor, receipt_cbor, receipt_unsigned, revocation_cbor, revocation_unsigned, signing_hash,
    verify_card, verify_operator_cert, verify_receipt, verify_revocation,
)

V = json.loads((Path(__file__).parent.parent / "test-vectors" / "v1.json").read_text())
AGENT = AgentKey.from_seed(V["keys"]["agent_seed"])
NODE = AgentKey.from_seed(V["keys"]["node_seed"])
OPERATOR = AgentKey.from_seed(V["keys"]["operator_seed"])
CERT = {**V["operator_cert"]["object"], "sig": V["operator_cert"]["sig"]}


def test_keys_and_agent_id():
    assert AGENT.public_key_hex == V["keys"]["agent_pubkey"]
    assert NODE.public_key_hex == V["keys"]["node_pubkey"]
    assert OPERATOR.public_key_hex == V["keys"]["operator_pubkey"]
    assert AGENT.agent_id == V["agent_id"]


def test_operator_cert():
    assert encode(operator_cert_cbor(CERT)).hex() == V["operator_cert"]["cbor"]
    assert OPERATOR.sign(bytes.fromhex(V["operator_cert"]["signing_hash"])).hex() == V["operator_cert"]["sig"]
    assert verify_operator_cert(CERT, CERT["issued_at"] + 1)


def test_card():
    card = {**V["card"]["object"], "operator_cert": CERT, "agent_sig": V["card"]["agent_sig"], "node_sig": V["card"]["node_sig"]}
    assert card_unsigned_bytes(card).hex() == V["card"]["unsigned_cbor"]
    assert card_agent_signing_hash(card).hex() == V["card"]["agent_signing_hash"]
    assert AGENT.sign(card_agent_signing_hash(card)).hex() == V["card"]["agent_sig"]
    assert card_node_signing_hash(card).hex() == V["card"]["node_signing_hash"]
    assert NODE.sign(card_node_signing_hash(card)).hex() == V["card"]["node_sig"]
    assert card_cbor(card).hex() == V["card"]["cbor"]
    assert verify_card(card) == (True, True)
    assert verify_card({**card, "traits": ["Plumber", "Astronomy enthusiast"]})[0] is False


def test_ephemeral():
    e = {**V["ephemeral"]["object"], "operator_cert": CERT, "agent_sig": V["ephemeral"]["agent_sig"], "node_sig": V["ephemeral"]["node_sig"]}
    assert encode(ephemeral_unsigned(e)).hex() == V["ephemeral"]["unsigned_cbor"]
    assert AGENT.sign(signing_hash(DOMAIN["ephemeral"], ephemeral_unsigned(e))).hex() == V["ephemeral"]["agent_sig"]
    assert ephemeral_cbor(e).hex() == V["ephemeral"]["cbor"]


def test_revocations():
    for name, signer in (("revocation_by_agent", AGENT), ("revocation_by_operator", OPERATOR)):
        r = {**V[name]["object"], "sig": V[name]["sig"]}
        assert encode(revocation_unsigned(r)).hex() == V[name]["unsigned_cbor"]
        assert signing_hash(DOMAIN["revocation"], revocation_unsigned(r)).hex() == V[name]["signing_hash"]
        assert signer.sign(bytes.fromhex(V[name]["signing_hash"])).hex() == V[name]["sig"]
        assert revocation_cbor(r).hex() == V[name]["cbor"]
        assert verify_revocation(r)


def test_receipts():
    for name in ("receipt_ok", "receipt_rejected"):
        r = {**V[name]["object"], "sig": V[name]["sig"]}
        assert signing_hash(DOMAIN["receipt"], receipt_unsigned(r)).hex() == V[name]["signing_hash"]
        assert receipt_cbor(r).hex() == V[name]["cbor"]
        assert verify_receipt(r)
        assert not verify_receipt({**r, "timestamp": r["timestamp"] + 1})

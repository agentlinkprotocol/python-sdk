"""Signed objects in their JSON (API) form and canonical CBOR views. Field order is the spec's."""

from __future__ import annotations

import os
import time
from typing import Any

from .canon import DOMAIN, signing_hash
from .cbor import encode
from .keys import AgentKey, agent_id_from_pubkey, verify

MODEL_V1 = "alp-embed-v1"
DAY = 86_400
CARD_MAX_TTL = 90 * DAY
EPHEMERAL_MAX_TTL = 7 * DAY


def now_secs() -> int:
    return int(time.time())


def _filters(f: dict | None) -> dict:
    f = f or {}
    return {"geohash": f.get("geohash"), "days": f.get("days"), "langs": list(f.get("langs") or [])}


def _h(x: str) -> bytes:
    return bytes.fromhex(x)


def operator_cert_cbor(c: dict) -> dict:
    return {"operator_pubkey": _h(c["operator_pubkey"]), "node_pubkey": _h(c["node_pubkey"]), "issued_at": c["issued_at"], "expires_at": c["expires_at"], "sig": _h(c["sig"])}


def _operator_cert_unsigned(c: dict) -> dict:
    return {"operator_pubkey": _h(c["operator_pubkey"]), "node_pubkey": _h(c["node_pubkey"]), "issued_at": c["issued_at"], "expires_at": c["expires_at"]}


def verify_operator_cert(c: dict, now: int | None = None) -> bool:
    now = now_secs() if now is None else now
    if now >= c["expires_at"]:
        return False
    return verify(_h(c["operator_pubkey"]), signing_hash(DOMAIN["opcert"], _operator_cert_unsigned(c)), _h(c["sig"]))


# ------------------------------------------------------------------ Card


def card_unsigned(c: dict) -> dict:
    return {
        "agent_id": c["agent_id"],
        "agent_pubkey": _h(c["agent_pubkey"]),
        "version": c["version"],
        "endpoints": list(c["endpoints"]),
        "traits": list(c["traits"]),
        "filters": _filters(c["filters"]),
        "model": c["model"],
        "map_version": c["map_version"],
        "issued_at": c["issued_at"],
        "expires_at": c["expires_at"],
        "operator_cert": operator_cert_cbor(c["operator_cert"]),
    }


def card_agent_signed(c: dict) -> dict:
    u = card_unsigned(c)
    out = {}
    for k, v in u.items():
        out[k] = v
        if k == "issued_at":
            out["last_seen"] = c["last_seen"]
    out["agent_sig"] = _h(c["agent_sig"])
    return out


def card_unsigned_bytes(c: dict) -> bytes:
    return encode(card_unsigned(c))


def card_agent_signing_hash(c: dict) -> bytes:
    return signing_hash(DOMAIN["card"], card_unsigned(c))


def card_node_signing_hash(c: dict) -> bytes:
    return signing_hash(DOMAIN["node_sig"], card_agent_signed(c))


def card_cbor(c: dict) -> bytes:
    d = card_agent_signed(c)
    d["node_sig"] = _h(c["node_sig"])
    return encode(d)


def make_card(agent: AgentKey, *, traits: list[str], operator_cert: dict, version: int, endpoints: list[str] | None = None,
              filters: dict | None = None, ttl: int = CARD_MAX_TTL, model: str = MODEL_V1, map_version: int = 1, issued_at: int | None = None) -> dict:
    """Build and sign a card. `operator_cert` comes from the node (GET /v1/status)."""
    issued = now_secs() if issued_at is None else issued_at
    card = {
        "agent_id": agent.agent_id,
        "agent_pubkey": agent.public_key_hex,
        "version": version,
        "endpoints": endpoints or [],
        "traits": traits,
        "filters": _filters(filters),
        "model": model,
        "map_version": map_version,
        "issued_at": issued,
        "last_seen": issued,
        "expires_at": issued + min(ttl, CARD_MAX_TTL),
        "operator_cert": operator_cert,
        "agent_sig": "00" * 64,
        "node_sig": "00" * 64,
    }
    card["agent_sig"] = agent.sign(card_agent_signing_hash(card)).hex()
    return card


def verify_card(c: dict) -> tuple[bool, bool]:
    """(agent signature valid, node countersignature valid)."""
    agent_ok = c["agent_id"] == agent_id_from_pubkey(_h(c["agent_pubkey"])) and verify(_h(c["agent_pubkey"]), card_agent_signing_hash(c), _h(c["agent_sig"]))
    node_ok = verify(_h(c["operator_cert"]["node_pubkey"]), card_node_signing_hash(c), _h(c["node_sig"]))
    return agent_ok, node_ok


# ------------------------------------------------------------------ Ephemeral


def ephemeral_unsigned(e: dict) -> dict:
    return {
        "agent_id": e["agent_id"],
        "agent_pubkey": _h(e["agent_pubkey"]),
        "ephemeral_id": _h(e["ephemeral_id"]),
        "text": e["text"],
        "filters": _filters(e["filters"]),
        "valid_from": e["valid_from"],
        "valid_until": e["valid_until"],
        "operator_cert": operator_cert_cbor(e["operator_cert"]),
    }


def ephemeral_cbor(e: dict) -> bytes:
    d = ephemeral_unsigned(e)
    d["agent_sig"] = _h(e["agent_sig"])
    d["node_sig"] = _h(e["node_sig"])
    return encode(d)


def make_ephemeral(agent: AgentKey, *, text: str, valid_from: int, valid_until: int, operator_cert: dict, filters: dict | None = None, ephemeral_id: bytes | None = None) -> dict:
    if valid_until - valid_from > EPHEMERAL_MAX_TTL:
        raise ValueError("ephemeral window longer than 7 days")
    e = {
        "agent_id": agent.agent_id,
        "agent_pubkey": agent.public_key_hex,
        "ephemeral_id": (ephemeral_id or os.urandom(16)).hex(),
        "text": text,
        "filters": _filters(filters),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "operator_cert": operator_cert,
        "agent_sig": "00" * 64,
        "node_sig": "00" * 64,
    }
    e["agent_sig"] = agent.sign(signing_hash(DOMAIN["ephemeral"], ephemeral_unsigned(e))).hex()
    return e


# ------------------------------------------------------------------ Revocation


def revocation_unsigned(r: dict) -> dict:
    t = r["target"]
    target = {"card": t["card"]} if "card" in t else {"ephemeral": _h(t["ephemeral"])}
    return {"agent_id": r["agent_id"], "target": target, "issued_at": r["issued_at"], "by": r["by"], "signer_pubkey": _h(r["signer_pubkey"])}


def revocation_cbor(r: dict) -> bytes:
    d = revocation_unsigned(r)
    d["sig"] = _h(r["sig"])
    return encode(d)


def make_revocation(agent: AgentKey, target: dict, issued_at: int | None = None) -> dict:
    """target = {"card": version} or {"ephemeral": hex id}."""
    r = {"agent_id": agent.agent_id, "target": target, "issued_at": now_secs() if issued_at is None else issued_at, "by": "agent", "signer_pubkey": agent.public_key_hex, "sig": "00" * 64}
    r["sig"] = agent.sign(signing_hash(DOMAIN["revocation"], revocation_unsigned(r))).hex()
    return r


def verify_revocation(r: dict) -> bool:
    return verify(_h(r["signer_pubkey"]), signing_hash(DOMAIN["revocation"], revocation_unsigned(r)), _h(r["sig"]))


# ------------------------------------------------------------------ Receipt


def receipt_unsigned(r: dict) -> dict:
    outcome: Any = r["outcome"] if isinstance(r["outcome"], str) else {"rejected": r["outcome"]["rejected"]}
    return {"node_pubkey": _h(r["node_pubkey"]), "request_hash": _h(r["request_hash"]), "kind": r["kind"], "timestamp": r["timestamp"], "outcome": outcome, "response_hash": _h(r["response_hash"])}


def receipt_cbor(r: dict) -> bytes:
    d = receipt_unsigned(r)
    d["sig"] = _h(r["sig"])
    return encode(d)


def verify_receipt(r: dict) -> bool:
    """A guardian's receipt is proof: verify it before trusting an answer."""
    return verify(_h(r["node_pubkey"]), signing_hash(DOMAIN["receipt"], receipt_unsigned(r)), _h(r["sig"]))

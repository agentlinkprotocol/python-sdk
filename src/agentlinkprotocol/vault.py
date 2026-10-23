"""Vault: encrypt with a key only the owner holds; the node splits into Reed-Solomon shards;
the agent signs each shard."""

from __future__ import annotations

import os

from .canon import DOMAIN, signing_hash
from .inbox import xchacha20poly1305_decrypt, xchacha20poly1305_encrypt
from .keys import AgentKey

VAULT_MAX_BYTES = 256 * 1024 * 1024


class VaultKey:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("vault key must be 32 bytes")
        self.key = key

    @classmethod
    def generate(cls) -> "VaultKey":
        return cls(os.urandom(32))

    @classmethod
    def from_hex(cls, h: str) -> "VaultKey":
        return cls(bytes.fromhex(h))

    def to_hex(self) -> str:
        return self.key.hex()


def _aad(agent_id: str, snapshot: int) -> bytes:
    return agent_id.encode() + snapshot.to_bytes(8, "big")


def encrypt_snapshot(key: VaultKey, agent_id: str, snapshot: int, plaintext: bytes) -> bytes:
    if len(plaintext) > VAULT_MAX_BYTES:
        raise ValueError("snapshot too large")
    nonce = os.urandom(24)
    return nonce + xchacha20poly1305_encrypt(key.key, nonce, plaintext, _aad(agent_id, snapshot))


def decrypt_snapshot(key: VaultKey, agent_id: str, snapshot: int, blob: bytes) -> bytes:
    return xchacha20poly1305_decrypt(key.key, blob[:24], blob[24:], _aad(agent_id, snapshot))


def shard_unsigned(s: dict) -> dict:
    return {
        "agent_id": s["agent_id"],
        "agent_pubkey": bytes.fromhex(s["agent_pubkey"]),
        "snapshot": s["snapshot"],
        "index": s["index"],
        "total": s["total"],
        "data_shards": s["data_shards"],
        "shard_hash": bytes.fromhex(s["shard_hash"]),
        "expires_at": s["expires_at"],
    }


def sign_shards(agent: AgentKey, shards: list[dict], snapshot: int, expires_at: int, operator_cert: dict) -> list[dict]:
    out = []
    for s in shards:
        base = {"agent_id": agent.agent_id, "agent_pubkey": agent.public_key_hex, "snapshot": snapshot, "index": s["index"], "total": s["total"], "data_shards": s["data_shards"], "shard_hash": s["shard_hash"], "expires_at": expires_at}
        sig = agent.sign(signing_hash(DOMAIN["vault"], shard_unsigned(base))).hex()
        out.append({**base, "data": s["data"], "operator_cert": operator_cert, "agent_sig": sig, "node_sig": "00" * 64})
    return out

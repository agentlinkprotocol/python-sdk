from __future__ import annotations

import base64
import os

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

AGENT_ID_PREFIX = "alp1"


def agent_id_from_pubkey(pubkey: bytes) -> str:
    """AgentId = "alp1" + lowercase base32 (no padding) of blake3(pubkey)[0..20]."""
    h = blake3.blake3(pubkey).digest()[:20]
    return AGENT_ID_PREFIX + base64.b32encode(h).decode().rstrip("=").lower()


def verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


class AgentKey:
    """An agent's Ed25519 identity. The seed never leaves the agent's process."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self.seed = seed
        self._priv = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key: bytes = self._priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.agent_id: str = agent_id_from_pubkey(self.public_key)

    @classmethod
    def generate(cls) -> "AgentKey":
        return cls(os.urandom(32))

    @classmethod
    def from_seed(cls, seed: bytes | str) -> "AgentKey":
        return cls(bytes.fromhex(seed) if isinstance(seed, str) else seed)

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    def export_seed(self) -> str:
        """Hex seed. Store it like a password: without it the agent is gone."""
        return self.seed.hex()

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    def x25519_private_bytes(self) -> bytes:
        """Clamped X25519 scalar derived like ed25519-dalek's `to_scalar_bytes()` (SHA-512 of the seed)."""
        import hashlib

        h = bytearray(hashlib.sha512(self.seed).digest()[:32])
        h[0] &= 248
        h[31] &= 127
        h[31] |= 64
        return bytes(h)

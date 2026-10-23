"""Sealed mailbox messages: eph_pub(32) || nonce(24) || XChaCha20-Poly1305(ct),
key = blake3("alp-seal-v1" || dh || eph_pub || recipient_ed25519_pub)."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .canon import DOMAIN, domain_hash, signing_hash
from .keys import AgentKey

INBOX_MAX_MESSAGE_BYTES = 64 * 1024
_P = 2**255 - 19


def _ed_to_x25519_pub(ed_pub: bytes) -> bytes:
    """Edwards y -> Montgomery u = (1 + y) / (1 - y) mod p (same as dalek's to_montgomery)."""
    y = int.from_bytes(bytes(ed_pub[:31]) + bytes([ed_pub[31] & 0x7F]), "little")
    u = (1 + y) * pow(1 - y, -1, _P) % _P
    return u.to_bytes(32, "little")


def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20 (RFC draft-irtf-cfrg-xchacha), to derive the XChaCha20 subkey."""

    def rotl(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def qr(s: list[int], a: int, b: int, c: int, d: int) -> None:
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] = rotl(s[b] ^ s[c], 7)

    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += [int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)]
    s += [int.from_bytes(nonce16[i : i + 4], "little") for i in range(0, 16, 4)]
    for _ in range(10):
        qr(s, 0, 4, 8, 12)
        qr(s, 1, 5, 9, 13)
        qr(s, 2, 6, 10, 14)
        qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15)
        qr(s, 1, 6, 11, 12)
        qr(s, 2, 7, 8, 13)
        qr(s, 3, 4, 9, 14)
    return b"".join(x.to_bytes(4, "little") for x in s[:4] + s[12:16])


def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    sub = _hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(sub).encrypt(b"\x00\x00\x00\x00" + nonce24[16:], plaintext, aad)


def xchacha20poly1305_decrypt(key: bytes, nonce24: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    sub = _hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(sub).decrypt(b"\x00\x00\x00\x00" + nonce24[16:], ciphertext, aad)


def seal(recipient_ed_pub: bytes, plaintext: bytes) -> bytes:
    if len(plaintext) + 72 > INBOX_MAX_MESSAGE_BYTES:
        raise ValueError("message too large")
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    dh = eph.exchange(X25519PublicKey.from_public_bytes(_ed_to_x25519_pub(recipient_ed_pub)))
    key = domain_hash(DOMAIN["seal"], dh + eph_pub + recipient_ed_pub)
    nonce = os.urandom(24)
    return eph_pub + nonce + xchacha20poly1305_encrypt(key, nonce, plaintext)


def open_sealed(recipient: AgentKey, sealed: bytes) -> bytes:
    if len(sealed) < 72:
        raise ValueError("sealed box too short")
    eph_pub, nonce, ct = sealed[:32], sealed[32:56], sealed[56:]
    dh = X25519PrivateKey.from_private_bytes(recipient.x25519_private_bytes()).exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = domain_hash(DOMAIN["seal"], dh + eph_pub + recipient.public_key)
    return xchacha20poly1305_decrypt(key, nonce, ct)


def fetch_auth_hash(agent_id: str, nonce: int) -> bytes:
    return domain_hash(DOMAIN["inbox_ack"], agent_id.encode() + nonce.to_bytes(8, "big"))


def sign_fetch(agent: AgentKey, nonce: int) -> str:
    return agent.sign(fetch_auth_hash(agent.agent_id, nonce)).hex()


def make_ack(agent: AgentKey, message_ids: list[str], issued_at: int) -> dict:
    unsigned = {"agent_id": agent.agent_id, "agent_pubkey": agent.public_key, "message_ids": [bytes.fromhex(m) for m in message_ids], "issued_at": issued_at}
    sig = agent.sign(signing_hash(DOMAIN["inbox_ack"], unsigned)).hex()
    return {"agent_id": agent.agent_id, "agent_pubkey": agent.public_key_hex, "message_ids": message_ids, "issued_at": issued_at, "sig": sig}

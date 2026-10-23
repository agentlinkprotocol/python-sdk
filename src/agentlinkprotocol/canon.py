from __future__ import annotations

from typing import Any

import blake3

from .cbor import encode

DOMAIN = {
    "card": b"alp-card-v1",
    "ephemeral": b"alp-ephemeral-v1",
    "revocation": b"alp-revocation-v1",
    "receipt": b"alp-receipt-v1",
    "opcert": b"alp-opcert-v1",
    "node_sig": b"alp-node-sig-v1",
    "ledger": b"alp-ledger-v1",
    "inbox_ack": b"alp-inbox-ack-v1",
    "vault": b"alp-vault-v1",
    "seal": b"alp-seal-v1",
}


def domain_hash(domain: bytes, payload: bytes) -> bytes:
    return blake3.blake3(domain + payload).digest()


def signing_hash(domain: bytes, unsigned: Any) -> bytes:
    """blake3(domain || canonical_cbor(unsigned view))."""
    return domain_hash(domain, encode(unsigned))


def b3(data: bytes) -> bytes:
    return blake3.blake3(data).digest()

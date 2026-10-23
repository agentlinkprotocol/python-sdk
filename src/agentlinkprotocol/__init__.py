"""Agent Link Protocol: Python SDK for the Atlas.

The SDK does three things the node never does: it holds the agent's keys, it signs (cards,
announcements, revocations, acks, shards) and it encrypts (mailbox, vault). Everything else is
a thin call to the Grid local API.
"""

from .canon import DOMAIN, domain_hash, signing_hash
from .cbor import encode
from .client import Grid, GridError
from .inbox import make_ack, open_sealed, seal, sign_fetch
from .keys import AgentKey, agent_id_from_pubkey, verify
from .objects import (
    CARD_MAX_TTL,
    EPHEMERAL_MAX_TTL,
    MODEL_V1,
    card_agent_signing_hash,
    card_cbor,
    card_node_signing_hash,
    card_unsigned_bytes,
    ephemeral_cbor,
    ephemeral_unsigned,
    make_card,
    make_ephemeral,
    make_revocation,
    operator_cert_cbor,
    receipt_cbor,
    receipt_unsigned,
    revocation_cbor,
    revocation_unsigned,
    verify_card,
    verify_operator_cert,
    verify_receipt,
    verify_revocation,
)
from .vault import VaultKey, decrypt_snapshot, encrypt_snapshot, sign_shards

__all__ = [
    "AgentKey", "agent_id_from_pubkey", "verify", "Grid", "GridError", "DOMAIN", "domain_hash", "signing_hash", "encode",
    "MODEL_V1", "CARD_MAX_TTL", "EPHEMERAL_MAX_TTL", "make_card", "make_ephemeral", "make_revocation", "verify_card", "verify_receipt",
    "verify_revocation", "verify_operator_cert", "card_cbor", "card_unsigned_bytes", "card_agent_signing_hash", "card_node_signing_hash",
    "ephemeral_cbor", "ephemeral_unsigned", "revocation_cbor", "revocation_unsigned", "receipt_cbor", "receipt_unsigned", "operator_cert_cbor",
    "seal", "open_sealed", "sign_fetch", "make_ack", "VaultKey", "encrypt_snapshot", "decrypt_snapshot", "sign_shards",
]

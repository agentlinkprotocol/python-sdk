"""Client of the Grid local API. Thin: one method per route of openapi.json. Signing stays here."""

from __future__ import annotations

import time
from typing import Any

import httpx

from .inbox import make_ack, open_sealed, seal, sign_fetch
from .keys import AgentKey
from .objects import make_card, make_ephemeral, make_revocation
from .vault import VaultKey, decrypt_snapshot, encrypt_snapshot, sign_shards


class GridError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status


class Grid:
    def __init__(self, base_url: str = "http://127.0.0.1:7777", token: str | None = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        headers = {"accept": "application/json"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        self._http = httpx.Client(base_url=self.base_url, headers=headers, timeout=timeout)
        self._status: dict | None = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "Grid":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        r = self._http.request(method, path, json=body)
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", r.text)
            except Exception:
                msg = r.text
            raise GridError(r.status_code, msg)
        return r.json()

    # ---- node
    def status(self) -> dict:
        self._status = self._call("GET", "/v1/status")
        return self._status

    def operator_cert(self) -> dict:
        if self._status is None:
            self.status()
        assert self._status is not None
        return self._status["operator_cert"]

    def atlas_stats(self) -> dict:
        return self._call("GET", "/v1/atlas/stats")

    def ledger(self, from_seq: int = 0, limit: int = 100) -> dict:
        return self._call("GET", f"/v1/ledger?from={from_seq}&limit={limit}")

    # ---- cards
    def publish(self, agent: AgentKey, *, traits: list[str], version: int, endpoints: list[str] | None = None, filters: dict | None = None, ttl: int | None = None) -> dict:
        """Build, sign and publish a card; the node fills `last_seen` and countersigns."""
        st = self.status()
        kwargs: dict[str, Any] = dict(traits=traits, version=version, endpoints=endpoints, filters=filters, operator_cert=st["operator_cert"], model=st["model"], map_version=st["map_version"])
        if ttl is not None:
            kwargs["ttl"] = ttl
        return self._call("POST", "/v1/cards", make_card(agent, **kwargs))

    def publish_signed(self, card: dict) -> dict:
        return self._call("POST", "/v1/cards", card)

    def get_card(self, agent_id: str) -> dict:
        return self._call("GET", f"/v1/cards/{agent_id}")

    def announce(self, agent: AgentKey, *, text: str, valid_from: int, valid_until: int, filters: dict | None = None) -> dict:
        return self._call("POST", "/v1/ephemerals", make_ephemeral(agent, text=text, valid_from=valid_from, valid_until=valid_until, filters=filters, operator_cert=self.operator_cert()))

    def revoke(self, agent: AgentKey, target: dict) -> dict:
        return self._call("POST", "/v1/revocations", make_revocation(agent, target))

    # ---- search
    def search(self, text: str, *, filters: dict | None = None, at: int | None = None, k: int | None = None) -> dict:
        return self._call("POST", "/v1/search", {"text": text, "filters": filters or {}, "at": at, "k": k})

    def embed(self, texts: list[str]) -> dict:
        return self._call("POST", "/v1/embed", {"texts": texts})

    # ---- inbox
    def send(self, sender: AgentKey, to_agent_id: str, to_pubkey_hex: str, plaintext: bytes | str) -> dict:
        data = plaintext.encode() if isinstance(plaintext, str) else plaintext
        sealed = seal(bytes.fromhex(to_pubkey_hex), data)
        return self._call("POST", "/v1/inbox", {"to": to_agent_id, "from_pubkey": sender.public_key_hex, "sealed": sealed.hex()})

    def receive(self, agent: AgentKey) -> list[dict]:
        """Pending messages, opened. Each: {id, from, deposited_at, plaintext}. Call ack() afterwards."""
        nonce = int(time.time())
        res = self._call("POST", f"/v1/inbox/{agent.agent_id}/fetch", {"agent_pubkey": agent.public_key_hex, "nonce": nonce, "auth": sign_fetch(agent, nonce)})
        out = []
        for m in res["messages"]:
            try:
                out.append({"id": m["message_id"], "from": m["from_pubkey"], "deposited_at": m["deposited_at"], "plaintext": open_sealed(agent, bytes.fromhex(m["ciphertext"]))})
            except Exception:
                continue
        return out

    def ack(self, agent: AgentKey, message_ids: list[str]) -> dict:
        return self._call("POST", f"/v1/inbox/{agent.agent_id}/ack", make_ack(agent, message_ids, int(time.time())))

    # ---- vault
    def backup(self, agent: AgentKey, key: VaultKey, snapshot: int, data: bytes, ttl: int = 365 * 86_400) -> dict:
        encrypted = encrypt_snapshot(key, agent.agent_id, snapshot, data)
        shards = self._call("POST", "/v1/vault/shards", {"encrypted": encrypted.hex()})["shards"]
        signed = sign_shards(agent, shards, snapshot, int(time.time()) + ttl, self.operator_cert())
        return self._call("PUT", f"/v1/vault/{agent.agent_id}", {"shards": signed})

    def restore(self, agent: AgentKey, key: VaultKey, snapshot: int) -> bytes:
        r = self._call("GET", f"/v1/vault/{agent.agent_id}/{snapshot}")
        if not r.get("encrypted"):
            raise GridError(404, f"only {r.get('shards_found')} shards found, cannot rebuild snapshot {snapshot}")
        return decrypt_snapshot(key, agent.agent_id, snapshot, bytes.fromhex(r["encrypted"]))

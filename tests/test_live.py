"""Runs against a live node when GRID_URL is set (and GRID_TOKEN or GRID_TOKEN_FILE)."""
import os
import time
from pathlib import Path

import pytest

from agentlinkprotocol import AgentKey, Grid, VaultKey, verify_card

URL = os.environ.get("GRID_URL")
TOKEN = os.environ.get("GRID_TOKEN") or (Path(os.environ["GRID_TOKEN_FILE"]).read_text().strip() if os.environ.get("GRID_TOKEN_FILE") else None)

pytestmark = pytest.mark.skipif(not URL, reason="GRID_URL not set")


def test_full_flow():
    with Grid(URL, TOKEN) as grid:
        st = grid.status()
        assert len(st["node_pubkey"]) == 64
        alice, bob = AgentKey.generate(), AgentKey.generate()
        r = grid.publish(alice, version=1, traits=["Python developer", "Chess enthusiast"], filters={"geohash": "u09tvw", "langs": ["fr", "en"]})
        assert r["card_copies"] > 0
        grid.publish(bob, version=1, traits=["Professional baker near Belleville"])
        found = grid.search("python developer chess", k=20)
        assert alice.agent_id in [x["agent_id"] for x in found["results"]]
        card = grid.get_card(alice.agent_id)["card"]
        assert verify_card(card) == (True, True)
        grid.send(alice, bob.agent_id, bob.public_key_hex, "bread order for tomorrow")
        msgs = grid.receive(bob)
        assert any(m["plaintext"] == b"bread order for tomorrow" for m in msgs)
        grid.ack(bob, [m["id"] for m in msgs])
        assert grid.receive(bob) == []
        key = VaultKey.generate()
        put = grid.backup(alice, key, 1, b'{"likes":"chess"}')
        assert put["shards_stored"] == 30
        assert grid.restore(alice, key, 1) == b'{"likes":"chess"}'
        grid.revoke(alice, {"card": 1})
        after = grid.search("python developer chess", at=int(time.time()) + 1, k=50)
        assert all(x["agent_id"] != alice.agent_id for x in after["results"])

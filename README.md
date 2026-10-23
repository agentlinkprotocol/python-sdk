# agentlinkprotocol

Python SDK for the **Agent Link Protocol Atlas**. It holds the agent's keys, **signs** (cards, announcements,
revocations, acks, vault shards) and **encrypts** (mailbox, vault); everything else is a thin client of the Grid
local API.

```bash
pip install agentlinkprotocol
```

```python
from agentlinkprotocol import AgentKey, Grid, VaultKey

grid = Grid("http://127.0.0.1:7777", token=open("~/.grid/api.token").read().strip())
me = AgentKey.generate()                      # keep me.export_seed() somewhere safe

grid.publish(me, version=1, traits=["Software developer", "Astronomy enthusiast"],
             filters={"geohash": "u09tvw", "langs": ["fr", "en"]})

found = grid.search("developer who loves astronomy", filters={"geohash": "u09t"})

grid.send(me, found["results"][0]["agent_id"], "<their pubkey hex>", "hello")
for m in grid.receive(me):
    print(m["plaintext"])
grid.ack(me, [m["id"] for m in grid.receive(me)])

key = VaultKey.generate()
grid.backup(me, key, 1, b'{"likes": "astronomy"}')
assert grid.restore(me, key, 1) == b'{"likes": "astronomy"}'
```

`tests/test_vectors.py` replays `test-vectors/v1.json` from the Rust node byte for byte. `verify_card`,
`verify_receipt`, `verify_revocation` let you check what a node hands you.

```bash
pip install -e ".[dev]" && pytest -q
GRID_URL=http://127.0.0.1:7777 GRID_TOKEN_FILE=~/.grid/api.token pytest -q tests/test_live.py
```

Apache-2.0.

## Branches and releases

Work on `develop`, open a pull request to `main` (`ci` runs on the pull request only: tests on Python 3.10/3.12/3.13, build). Merging into `main`
publishes `pyproject.toml`'s version to PyPI through trusted publishing (environment `pypi`, no token) and tags
`vX.Y.Z`. Bump the version on `develop` before merging.

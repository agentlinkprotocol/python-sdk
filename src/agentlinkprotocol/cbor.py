"""Canonical CBOR encoder for Atlas signed objects (byte-identical to alp-grid-core::canon).

Maps keep insertion order (the spec's declaration order), integers use the shortest form,
bytes -> bstr, str -> tstr, None -> null, bool -> true/false, lists -> definite arrays.
Floats are refused: signed objects never contain them.
"""

from __future__ import annotations

from typing import Any


def _head(major: int, n: int, out: bytearray) -> None:
    m = major << 5
    if n < 24:
        out.append(m | n)
    elif n < 0x100:
        out += bytes([m | 24, n])
    elif n < 0x10000:
        out += bytes([m | 25]) + n.to_bytes(2, "big")
    elif n < 0x1_0000_0000:
        out += bytes([m | 26]) + n.to_bytes(4, "big")
    else:
        out += bytes([m | 27]) + n.to_bytes(8, "big")


def _encode(v: Any, out: bytearray) -> None:
    if v is None:
        out.append(0xF6)
    elif v is True:
        out.append(0xF5)
    elif v is False:
        out.append(0xF4)
    elif isinstance(v, int):
        if v >= 0:
            _head(0, v, out)
        else:
            _head(1, -1 - v, out)
    elif isinstance(v, float):
        raise TypeError("floats are not allowed in signed objects")
    elif isinstance(v, str):
        b = v.encode("utf-8")
        _head(3, len(b), out)
        out += b
    elif isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        _head(2, len(b), out)
        out += b
    elif isinstance(v, (list, tuple)):
        _head(4, len(v), out)
        for x in v:
            _encode(x, out)
    elif isinstance(v, dict):
        _head(5, len(v), out)
        for k, x in v.items():
            _encode(k, out)
            _encode(x, out)
    else:
        raise TypeError(f"cannot encode {type(v).__name__}")


def encode(v: Any) -> bytes:
    out = bytearray()
    _encode(v, out)
    return bytes(out)

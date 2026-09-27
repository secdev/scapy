#!/usr/bin/env python3
"""Generate a reproducible CBOR corpus with cbor2 6.1.4.

The UTS campaign performs live differential checks. This helper freezes the
same style of independently generated vectors into JSON for debugging,
minimization, or CI systems that prefer checked-in fixtures.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any

import cbor2

VERSION = "6.1.4"
DEFAULT_SEED = 0xCB020301


def random_key(rng: random.Random) -> Any:
    kind = rng.randrange(3)
    if kind == 0:
        return rng.randint(-100000, 100000)
    if kind == 1:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(8)))
    alphabet = "abcXYZ012-_ä"
    return "".join(rng.choice(alphabet) for _ in range(rng.randrange(8)))


def random_value(rng: random.Random, depth: int = 0) -> Any:
    kinds = [
        "uint", "nint", "bytes", "text", "bool", "null", "undefined",
        "simple", "float", "tag",
    ]
    if depth < 4:
        kinds.extend(("array", "map"))
    kind = rng.choice(kinds)
    if kind == "uint":
        return rng.randrange(0, 1 << rng.choice((4, 8, 16, 32, 64)))
    if kind == "nint":
        return -1 - rng.randrange(0, 1 << rng.choice((4, 8, 16, 32, 63)))
    if kind == "bytes":
        return bytes(rng.randrange(256) for _ in range(rng.randrange(32)))
    if kind == "text":
        alphabet = "abcXYZ012-_ä€𐍈\x00"
        return "".join(rng.choice(alphabet) for _ in range(rng.randrange(24)))
    if kind == "bool":
        return bool(rng.getrandbits(1))
    if kind == "null":
        return None
    if kind == "undefined":
        return cbor2.undefined
    if kind == "simple":
        return cbor2.CBORSimpleValue(rng.choice((0, 1, 16, 19, 32, 64, 127, 255)))
    if kind == "float":
        special = rng.randrange(12)
        if special == 0:
            return -0.0
        if special == 1:
            return float("inf")
        if special == 2:
            return float("-inf")
        if special == 3:
            return float("nan")
        return rng.uniform(-1.0e12, 1.0e12)
    if kind == "tag":
        return cbor2.CBORTag(60000 + rng.randrange(1000), random_value(rng, depth + 1))
    if kind == "array":
        return [random_value(rng, depth + 1) for _ in range(rng.randrange(6))]

    result: dict[Any, Any] = {}
    target = rng.randrange(6)
    while len(result) < target:
        result[random_key(rng)] = random_value(rng, depth + 1)
    return result


def json_repr(value: Any) -> Any:
    if value is cbor2.undefined:
        return {"type": "undefined"}
    if isinstance(value, cbor2.CBORSimpleValue):
        return {"type": "simple", "value": value.value}
    if isinstance(value, cbor2.CBORTag):
        return {"type": "tag", "tag": value.tag, "value": json_repr(value.value)}
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, float):
        if math.isnan(value):
            return {"type": "float", "value": "nan"}
        if math.isinf(value):
            return {"type": "float", "value": "+inf" if value > 0 else "-inf"}
        if value == 0.0 and math.copysign(1.0, value) < 0:
            return {"type": "float", "value": "-0"}
        return value
    if isinstance(value, dict):
        return {
            "type": "map",
            "pairs": [[json_repr(key), json_repr(item)] for key, item in value.items()],
        }
    if isinstance(value, (list, tuple)):
        return [json_repr(item) for item in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=DEFAULT_SEED)
    parser.add_argument("--count", type=int, default=512)
    args = parser.parse_args()

    actual_version = distribution_version("cbor2")
    if actual_version != VERSION:
        parser.error(f"expected cbor2 {VERSION}, found {actual_version}")

    rng = random.Random(args.seed)
    vectors = []
    for index in range(args.count):
        value = random_value(rng)
        default_wire = cbor2.dumps(value)
        canonical_wire = cbor2.dumps(value, canonical=True)
        indefinite_wire = cbor2.dumps(value, indefinite_containers=True)
        vectors.append({
            "index": index,
            "value": json_repr(value),
            "default_hex": default_wire.hex(),
            "canonical_hex": canonical_wire.hex(),
            "indefinite_hex": indefinite_wire.hex(),
        })

    document = {
        "generator": "cbor2",
        "generator_version": actual_version,
        "seed": args.seed,
        "count": args.count,
        "vectors": vectors,
    }
    args.output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

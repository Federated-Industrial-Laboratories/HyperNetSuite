#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent recursive RFC 9162 vectors; the Rust verifier walks positions iteratively."""
import functools
import hashlib
import json
from pathlib import Path


def node(index):
    return hashlib.sha256(b"HyperNetHistoryVectors/1\0" + index.to_bytes(8, "big")).digest()


@functools.lru_cache(maxsize=None)
def tree(start, size):
    if size == 1:
        return hashlib.sha256(b"\0" + node(start)).digest()
    split = 1 << ((size - 1).bit_length() - 1)
    return hashlib.sha256(b"\1" + tree(start, split) + tree(start + split, size - split)).digest()


def inclusion(index, start, size):
    if size == 1:
        return []
    split = 1 << ((size - 1).bit_length() - 1)
    if index < split:
        return inclusion(index, start, split) + [tree(start + split, size - split)]
    return inclusion(index - split, start + split, size - split) + [tree(start, split)]


def consistency(old, start, size, known=True):
    if old == size:
        return [] if known else [tree(start, size)]
    split = 1 << ((size - 1).bit_length() - 1)
    if old <= split:
        return consistency(old, start, split, known) + [tree(start + split, size - split)]
    return consistency(old - split, start + split, size - split, False) + [tree(start, split)]


def main():
    selected = [(1, 0), (2, 0), (2, 1), (3, 2), (7, 0), (7, 3), (7, 4), (7, 6),
                (17, 8), (17, 16), (32, 31), (33, 32), (65, 31), (65, 64),
                (131072, 65535), (131072, 131071)]
    pairs = [(1, 2), (1, 33), (3, 7), (4, 7), (6, 7), (16, 17), (17, 33),
             (31, 65), (32, 65), (63, 65), (65, 65), (65535, 131072), (65536, 131072)]
    result = {
        "format": "HyperNetHistoryVectors/1",
        "specification": "https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1",
        "inclusion": [{"size": size, "index": index, "node": node(index).hex(),
                       "root": tree(0, size).hex(), "path": [v.hex() for v in inclusion(index, 0, size)]}
                      for size, index in selected],
        "consistency": [{"oldSize": old, "size": size, "oldRoot": tree(0, old).hex(),
                         "root": tree(0, size).hex(), "path": [v.hex() for v in consistency(old, 0, size)]}
                        for old, size in pairs],
    }
    Path(__file__).with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()

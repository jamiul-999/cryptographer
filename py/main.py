#!/usr/bin/env python3

import sys
import json
import time

from classical.substitution      import handle as substitution_handle
from classical.double_transposition import handle as double_transposition_handle
from symmetric.des               import handle as des_handle
from symmetric.aes               import handle as aes_handle
from asymmetric.rsa              import handle as rsa_handle
from asymmetric.ecc              import handle as ecc_handle

ROUTER = {
    "substitution":        substitution_handle,
    "double_transposition": double_transposition_handle,
    "des":                 des_handle,
    "aes":                 aes_handle,
    "rsa":                 rsa_handle,
    "ecc":                 ecc_handle,
}


def main():
    raw = sys.stdin.read()
    try:
        req = json.loads(raw)
    except json.JSONDecodeError as e:
        _respond({}, 0.0, f"Invalid JSON input: {e}")
        return

    algo = req.get("algorithm", "")
    handler = ROUTER.get(algo)
    if handler is None:
        _respond({}, 0.0, f"Unknown algorithm: '{algo}'")
        return

    start = time.perf_counter()
    try:
        output = handler(req.get("operation", ""), req.get("params", {}))
        elapsed = (time.perf_counter() - start) * 1000
        _respond(output, elapsed, "")
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        _respond({}, elapsed, str(e))


def _respond(output: dict, elapsed_ms: float, error: str):
    print(json.dumps({
        "output":     output,
        "elapsed_ms": round(elapsed_ms, 4),
        "error":      error,
    }))


if __name__ == "__main__":
    main()

"""
ECC (Elliptic Curve Cryptography) — Public-Key Cryptography
=============================================================
Elliptic curve arithmetic over Fp from scratch.
Supports custom domain parameters (p, a, b, G, n) or standard NIST P-256.

Operations
----------
  list  — enumerate all scalar multiples of P, then generate a key pair
  ecdh  — perform ECDH: given both private keys, compute shared secret
"""

import secrets

# ─────────────────────────────────────────────
# NIST P-256 Domain Parameters (default)
# ─────────────────────────────────────────────

P256 = {
    "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    "Gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    "Gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    "n":  0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
}

INF = (None, None)  # Point at infinity


# ─────────────────────────────────────────────
# Modular arithmetic helpers
# ─────────────────────────────────────────────

def _modinv(a: int, m: int) -> int:
    g, x, _ = _ext_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m


def _ext_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _ext_gcd(b % a, a)
    return g, y - (b // a) * x, x


# ─────────────────────────────────────────────
# EC Point Operations
# ─────────────────────────────────────────────

def _point_add(P, Q, a: int, p: int):
    """Add two points on the elliptic curve y² = x³ + ax + b over Fp."""
    if P == INF:
        return Q
    if Q == INF:
        return P

    px, py = P
    qx, qy = Q

    if px == qx:
        if py != qy:
            return INF
        if py == 0:
            return INF
        lam = (3 * px * px + a) * _modinv(2 * py, p) % p
    else:
        lam = (qy - py) * _modinv(qx - px, p) % p

    rx = (lam * lam - px - qx) % p
    ry = (lam * (px - rx) - py) % p
    return (rx, ry)


def _point_mul(k: int, P, a: int, p: int):
    """Scalar multiplication: k * P using double-and-add."""
    result = INF
    addend = P
    while k:
        if k & 1:
            result = _point_add(result, addend, a, p)
        addend = _point_add(addend, addend, a, p)
        k >>= 1
    return result


def _is_non_singular(a: int, b: int, p: int) -> bool:
    return (4 * a**3 + 27 * b**2) % p != 0


# ─────────────────────────────────────────────
# Public Handle
# ─────────────────────────────────────────────

def handle(operation: str, params: dict) -> dict:
    op = operation.lower()

    def _get_params():
        # Use custom params if 'p' is explicitly provided (works without use_default flag too).
        use_default = params.get("use_default", "true").lower() != "false"
        if params.get("p", "") != "":
            use_default = False
        if use_default:
            dp = P256
            return dp["p"], dp["a"], dp["b"], (dp["Gx"], dp["Gy"]), dp["n"]
        try:
            p  = int(params.get("p",  "17"))
            a  = int(params.get("a",  "2"))
            b  = int(params.get("b",  "2"))
            Gx = int(params.get("Gx", "5"))
            Gy = int(params.get("Gy", "1"))
            # n is optional — list derives it by enumeration; ecdh requires it
            n_str = params.get("n", "")
            n  = int(n_str) if n_str else None
        except ValueError as e:
            raise ValueError(f"Invalid curve parameter: {e}")
        return p, a, b, (Gx, Gy), n

    def _parse_or_rand(key: str, n: int) -> int:
        val = params.get(key, "0").strip()
        if val and val != "0":
            try:
                return int(val)
            except ValueError:
                raise ValueError(f"Invalid private key '{key}': must be a decimal integer")
        return secrets.randbelow(n - 1) + 1

    if op == "list":
        p, a, b, G, n = _get_params()
        use_default = params.get("use_default", "true").lower() != "false"
        if not use_default and not _is_non_singular(a, b, p):
            raise ValueError("Custom curve is singular (4a³ + 27b² ≡ 0 mod p): group law is undefined")
        if n is not None and n > 10000:
            return {"error": "p too large for enumeration"}

        # Enumerate all scalar multiples of G (1P, 2P, … until ∞)
        lines = []
        current = G
        k = 1
        while True:
            lines.append(f"{k}P = ({current[0]}, {current[1]})")
            nxt = _point_add(current, G, a, p)
            k += 1
            if nxt == INF:
                lines.append(f"{k}P = ∞")
                break
            current = nxt

        order = k
        priv_key = secrets.randbelow(order - 1) + 1
        pub_key = _point_mul(priv_key, G, a, p)

        return {
            "number_of_ps": str(order),
            "all_ps":        "\n".join(lines),
            "private_key":   str(priv_key),
            "public_key":    f"({pub_key[0]}, {pub_key[1]})",
        }

    elif op == "ecdh":
        p, a, b, G, n = _get_params()
        use_default = params.get("use_default", "true").lower() != "false"
        if not use_default and not _is_non_singular(a, b, p):
            raise ValueError("Custom curve is singular (4a³ + 27b² ≡ 0 mod p): group law is undefined")

        ka = _parse_or_rand("ka", n)
        kb = _parse_or_rand("kb", n)

        Qa = _point_mul(ka, G, a, p)
        Qb = _point_mul(kb, G, a, p)
        shared = _point_mul(ka, Qb, a, p)

        return {
            "shared_key": f"({shared[0]}, {shared[1]})",
        }

    else:
        raise ValueError(f"Unknown operation '{operation}' for ECC.")

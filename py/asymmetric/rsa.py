"""
RSA — Public-Key Cryptography
==============================
Full RSA from scratch: key generation, encrypt, decrypt, factorization attack.
Uses only Python's built-in integer arithmetic (no crypto libs).

Operations
----------
  generate  — generate RSA key pair for given bit size
  encrypt   — encrypt plaintext string with public key
  decrypt   — decrypt ciphertext integer with private key
  factorize — Pollard's rho factorization attack on n (for demo / small keys)
"""

import os
import math
import random
import secrets


# ─────────────────────────────────────────────
# Number Theory Helpers
# ─────────────────────────────────────────────

def _is_prime_miller_rabin(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test."""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a random prime of exactly `bits` bits."""
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1  # ensure odd, correct length
        if _is_prime_miller_rabin(n):
            return n


def _mod_inverse(e: int, phi: int) -> int:
    """Extended Euclidean Algorithm to find modular inverse."""
    g, x, _ = _extended_gcd(e, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % phi


def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


# ─────────────────────────────────────────────
# RSA Key Generation
# ─────────────────────────────────────────────

def _generate_keypair(bits: int):
    half = bits // 2
    p = _generate_prime(half)
    q = _generate_prime(half)
    while q == p:
        q = _generate_prime(half)

    n   = p * q
    phi = (p - 1) * (q - 1)

    # Common public exponent
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    d = _mod_inverse(e, phi)
    return {"p": p, "q": q, "n": n, "e": e, "d": d, "phi": phi}


# ─────────────────────────────────────────────
# OAEP-lite Padding (simplified, for demo)
# We use textbook RSA with a length prefix for educational clarity.
# ─────────────────────────────────────────────

def _text_to_int(text: str) -> int:
    return int(text.encode().hex(), 16)


def _int_to_text(n: int) -> str:
    h = hex(n)[2:]
    if len(h) % 2:
        h = "0" + h
    return bytes.fromhex(h).decode(errors="replace")


# ─────────────────────────────────────────────
# Pollard's Rho Factorization
# ─────────────────────────────────────────────

def _pollards_rho(n: int, max_iter: int = 100_000) -> int | None:
    """Returns a non-trivial factor of n, or None if not found."""
    if n % 2 == 0:
        return 2
    x = secrets.randbelow(n - 2) + 2
    y = x
    c = secrets.randbelow(n - 1) + 1
    d = 1
    steps = 0
    while d == 1 and steps < max_iter:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)
        steps += 1
    return d if d != n else None


def _factorize(n: int, timeout_iters: int = 20) -> tuple[int, int]:
    """Attempt to factor n into (p, q). Returns (0, 0) on failure."""
    for _ in range(timeout_iters):
        f = _pollards_rho(n)
        if f is None or not (1 < f < n):
            continue
        return f, n // f
    return 0, 0


# ─────────────────────────────────────────────
# Public Handle
# ─────────────────────────────────────────────

def handle(operation: str, params: dict) -> dict:
    op = operation.lower()

    if op == "generate":
        bits = int(params.get("key_size", 512))
        if bits not in (256, 512, 1024, 2048):
            bits = 512
        keys = _generate_keypair(bits)
        return {
            "public_key_n":  str(keys["n"]),
            "public_key_e":  str(keys["e"]),
            "private_key_d": str(keys["d"]),
            "prime_p":       str(keys["p"]),
            "prime_q":       str(keys["q"]),
            "phi_n":         str(keys["phi"]),
            "key_size":      f"{bits} bits",
        }

    elif op == "encrypt":
        plaintext = params.get("plaintext", "")
        n         = int(params.get("n", "0"))
        e         = int(params.get("e", "65537"))
        m         = _text_to_int(plaintext)
        if m >= n:
            raise ValueError("Message too large for key size.")
        c = pow(m, e, n)
        return {
            "ciphertext_int": str(c),
            "ciphertext_hex": hex(c),
        }

    elif op == "decrypt":
        c = int(params.get("ciphertext", "0"))
        n = int(params.get("n", "0"))
        d = int(params.get("d", "0"))
        m = pow(c, d, n)
        plaintext = _int_to_text(m)
        return {"plaintext": plaintext}

    elif op == "factorize":
        n = int(params.get("n", "0"))
        if _is_prime_miller_rabin(n):
            return {"result": f"{n} is prime — cannot factor."}
        p, q = _factorize(n)
        if p == 0:
            return {"result": "Factorization failed (n too large or took too long)."}
        if p * q != n:
            return {"result": "Factorization returned invalid factors."}
        # Recover private key
        e   = int(params.get("e", "65537"))
        phi = (p - 1) * (q - 1)
        try:
            d = _mod_inverse(e, phi)
            d_str = str(d)
        except Exception:
            d_str = "could not compute"
        return {
            "factor_p":          str(p),
            "factor_q":          str(q),
            "recovered_phi":     str(phi),
            "recovered_private": d_str,
        }

    else:
        raise ValueError(f"Unknown operation '{operation}' for RSA.")

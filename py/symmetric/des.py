"""
DES (Data Encryption Standard) — Symmetric-Key Cryptography
=============================================================
Full 16-round Feistel DES implemented from scratch.
Key is auto-generated (random 64-bit, 8 bytes).

Operations
----------
  encrypt — encrypt plaintext with auto-generated key, ECB mode (block-by-block)
  decrypt — decrypt ciphertext with the provided key
"""

import os
import binascii

# ─────────────────────────────────────────────
# DES TABLES (all 1-indexed, converted to 0-indexed internally)
# ─────────────────────────────────────────────

# Initial Permutation (IP)
IP = [
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
]

# Final Permutation (IP^-1)
IP_INV = [
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25,
]

# Expansion (E)
E = [
    32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
    12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1,
]

# Permutation (P)
P = [
    16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25,
]

# PC-1: 64-bit key → 56-bit (discard parity bits)
PC1 = [
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4,
]

# PC-2: 56-bit → 48-bit subkey
PC2 = [
    14,17,11,24,1,5, 3,28,15,6,21,10,
    23,19,12,4,26,8, 16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32,
]

# Left shifts per round
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# S-Boxes (8 boxes, each 4×16)
SBOXES = [
    # S1
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    # S2
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    # S3
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    # S4
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    # S5
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    # S6
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    # S7
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    # S8
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]


# ─────────────────────────────────────────────
# Core Helpers
# ─────────────────────────────────────────────

def _permute(bits: list[int], table: list[int]) -> list[int]:
    return [bits[t - 1] for t in table]


def _xor(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def _int_to_bits(n: int, length: int) -> list[int]:
    return [(n >> (length - 1 - i)) & 1 for i in range(length)]


def _bits_to_int(bits: list[int]) -> int:
    result = 0
    for b in bits:
        result = (result << 1) | b
    return result


def _bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        bits.extend(_int_to_bits(byte, 8))
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits), 8):
        result.append(_bits_to_int(bits[i:i+8]))
    return bytes(result)


def _left_rotate(bits: list[int], n: int) -> list[int]:
    return bits[n:] + bits[:n]


# ─────────────────────────────────────────────
# Key Schedule — generate 16 round keys
# ─────────────────────────────────────────────

def _generate_round_keys(key_bytes: bytes) -> list[list[int]]:
    key_bits = _bytes_to_bits(key_bytes)
    key56    = _permute(key_bits, PC1)
    C, D     = key56[:28], key56[28:]
    round_keys = []
    for shift in SHIFTS:
        C = _left_rotate(C, shift)
        D = _left_rotate(D, shift)
        CD = C + D
        round_keys.append(_permute(CD, PC2))
    return round_keys


# ─────────────────────────────────────────────
# Feistel Function f(R, K)
# ─────────────────────────────────────────────

def _feistel(R: list[int], K: list[int]) -> list[int]:
    # Expand R from 32 → 48 bits
    R_exp = _permute(R, E)
    # XOR with round key
    xored = _xor(R_exp, K)
    # S-Box substitution: 48 → 32 bits
    sbox_out = []
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = _bits_to_int(chunk[1:5])
        sbox_out.extend(_int_to_bits(SBOXES[i][row][col], 4))
    # Permutation P
    return _permute(sbox_out, P)


# ─────────────────────────────────────────────
# Encrypt / Decrypt a single 64-bit block
# ─────────────────────────────────────────────

def _des_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    bits = _bytes_to_bits(block)
    bits = _permute(bits, IP)
    L, R = bits[:32], bits[32:]
    for K in round_keys:
        L, R = R, _xor(L, _feistel(R, K))
    combined = _permute(R + L, IP_INV)
    return _bits_to_bytes(combined)


def _pad_pkcs5(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def _unpad_pkcs5(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# ─────────────────────────────────────────────
# Public Handle
# ─────────────────────────────────────────────

def handle(operation: str, params: dict) -> dict:
    op = operation.lower()

    if op == "encrypt":
        plaintext  = params.get("plaintext", "").encode()
        # Auto-generate an 8-byte key (64 bits)
        key_bytes  = os.urandom(8)
        key_hex    = key_bytes.hex().upper()
        round_keys = _generate_round_keys(key_bytes)

        padded     = _pad_pkcs5(plaintext)
        ciphertext = b""
        for i in range(0, len(padded), 8):
            ciphertext += _des_block(padded[i:i+8], round_keys)

        cipher_hex = ciphertext.hex().upper()

        # Format round keys as hex strings
        rk_lines = []
        for idx, rk in enumerate(round_keys, 1):
            rk_bytes = _bits_to_bytes(rk + [0] * (64 - len(rk)))
            rk_lines.append(f"Round {idx:2d}: {rk_bytes.hex().upper()[:12]}")

        return {
            "key_hex":    key_hex,
            "ciphertext": cipher_hex,
            "round_keys": "\n".join(rk_lines),
            "block_size": "64 bits (8 bytes)",
            "mode":       "ECB",
        }

    elif op == "decrypt":
        cipher_hex = params.get("ciphertext", "")
        key_hex    = params.get("key", "")
        key_bytes  = bytes.fromhex(key_hex)
        round_keys = _generate_round_keys(key_bytes)
        # Decryption uses reversed round keys
        dec_keys   = list(reversed(round_keys))

        ciphertext = bytes.fromhex(cipher_hex)
        decrypted  = b""
        for i in range(0, len(ciphertext), 8):
            decrypted += _des_block(ciphertext[i:i+8], dec_keys)

        plaintext = _unpad_pkcs5(decrypted).decode(errors="replace")
        return {"plaintext": plaintext}

    else:
        raise ValueError(f"Unknown operation '{operation}' for DES.")

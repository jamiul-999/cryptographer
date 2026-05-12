"""
AES (Advanced Encryption Standard) — Symmetric-Key Cryptography
================================================================
Full AES-128/192/256 implemented from scratch.
Key is auto-generated. CBC mode with PKCS7 padding.

Operations
----------
  encrypt — encrypt plaintext, returns key, IV, ciphertext, all round keys
  decrypt — decrypt ciphertext given key and IV
"""

import os

# ─────────────────────────────────────────────
# AES CONSTANTS
# ─────────────────────────────────────────────

# AES S-Box
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# Inverse S-Box
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Rcon for key expansion
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


# ─────────────────────────────────────────────
# GF(2^8) arithmetic
# ─────────────────────────────────────────────

def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _gmul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


# ─────────────────────────────────────────────
# AES State operations (4×4 byte matrix)
# ─────────────────────────────────────────────

def _sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[SBOX[b] for b in row] for row in state]


def _inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[INV_SBOX[b] for b in row] for row in state]


def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]


def _inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    return [
        state[0],
        state[1][-1:] + state[1][:-1],
        state[2][-2:] + state[2][:-2],
        state[3][-3:] + state[3][:-3],
    ]


def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    new = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new[0][c] = _gmul(col[0],2)^_gmul(col[1],3)^col[2]^col[3]
        new[1][c] = col[0]^_gmul(col[1],2)^_gmul(col[2],3)^col[3]
        new[2][c] = col[0]^col[1]^_gmul(col[2],2)^_gmul(col[3],3)
        new[3][c] = _gmul(col[0],3)^col[1]^col[2]^_gmul(col[3],2)
    return new


def _inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    new = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new[0][c] = _gmul(col[0],0x0e)^_gmul(col[1],0x0b)^_gmul(col[2],0x0d)^_gmul(col[3],0x09)
        new[1][c] = _gmul(col[0],0x09)^_gmul(col[1],0x0e)^_gmul(col[2],0x0b)^_gmul(col[3],0x0d)
        new[2][c] = _gmul(col[0],0x0d)^_gmul(col[1],0x09)^_gmul(col[2],0x0e)^_gmul(col[3],0x0b)
        new[3][c] = _gmul(col[0],0x0b)^_gmul(col[1],0x0d)^_gmul(col[2],0x09)^_gmul(col[3],0x0e)
    return new


def _add_round_key(state: list[list[int]], rk: list[list[int]]) -> list[list[int]]:
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


def _bytes_to_state(block: bytes) -> list[list[int]]:
    # Column-major: state[row][col]
    state = [[0]*4 for _ in range(4)]
    for i, byte in enumerate(block):
        state[i % 4][i // 4] = byte
    return state


def _state_to_bytes(state: list[list[int]]) -> bytes:
    result = []
    for c in range(4):
        for r in range(4):
            result.append(state[r][c])
    return bytes(result)


# ─────────────────────────────────────────────
# Key Expansion
# ─────────────────────────────────────────────

def _key_expansion(key: bytes):
    """Returns list of round key matrices (each is 4×4 list of ints)."""
    key_len = len(key)  # 16, 24, or 32
    nk      = key_len // 4
    nr      = nk + 6   # 10, 12, 14 rounds

    # W is a list of 4-byte words
    W = [list(key[i*4:(i+1)*4]) for i in range(nk)]

    for i in range(nk, 4*(nr+1)):
        temp = list(W[i-1])
        if i % nk == 0:
            # RotWord + SubWord + Rcon
            temp = [SBOX[b] for b in (temp[1:] + temp[:1])]
            temp[0] ^= RCON[(i//nk)-1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        W.append([a ^ b for a, b in zip(W[i-nk], temp)])

    # Convert words to 4×4 round key matrices
    round_keys = []
    for rnd in range(nr+1):
        rk = [[0]*4 for _ in range(4)]
        for c in range(4):
            word = W[rnd*4 + c]
            for r in range(4):
                rk[r][c] = word[r]
        round_keys.append(rk)

    return round_keys, nr


# ─────────────────────────────────────────────
# AES Block Encrypt / Decrypt
# ─────────────────────────────────────────────

def _aes_encrypt_block(block: bytes, round_keys: list, nr: int) -> bytes:
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])
    for rnd in range(1, nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[nr])
    return _state_to_bytes(state)


def _aes_decrypt_block(block: bytes, round_keys: list, nr: int) -> bytes:
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[nr])
    for rnd in range(nr-1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad] * pad)


def _pkcs7_unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


# ─────────────────────────────────────────────
# Public Handle
# ─────────────────────────────────────────────

def handle(operation: str, params: dict) -> dict:
    op = operation.lower()

    if op == "encrypt":
        plaintext  = params.get("plaintext", "").encode()
        key_size   = int(params.get("key_size", 128))
        if key_size not in (128, 192, 256):
            key_size = 128
        key_bytes  = os.urandom(key_size // 8)
        iv         = os.urandom(16)
        key_hex    = key_bytes.hex().upper()
        iv_hex     = iv.hex().upper()

        round_keys, nr = _key_expansion(key_bytes)

        # CBC encryption
        padded = _pkcs7_pad(plaintext)
        prev   = iv
        ciphertext = b""
        for i in range(0, len(padded), 16):
            block   = bytes(a^b for a,b in zip(padded[i:i+16], prev))
            enc     = _aes_encrypt_block(block, round_keys, nr)
            ciphertext += enc
            prev    = enc

        cipher_hex = ciphertext.hex().upper()

        # Format round keys
        rk_lines = []
        for idx, rk in enumerate(round_keys):
            flat = bytes(rk[r][c] for c in range(4) for r in range(4))
            rk_lines.append(f"Round {idx:2d}: {flat.hex().upper()}")

        return {
            "key_hex":    key_hex,
            "key_size":   f"AES-{key_size}",
            "iv_hex":     iv_hex,
            "ciphertext": cipher_hex,
            "round_keys": "\n".join(rk_lines),
            "rounds":     str(nr),
            "mode":       "CBC",
        }

    elif op == "decrypt":
        cipher_hex = params.get("ciphertext", "")
        key_hex    = params.get("key", "")
        iv_hex     = params.get("iv", "")
        key_bytes  = bytes.fromhex(key_hex)
        iv         = bytes.fromhex(iv_hex)

        round_keys, nr = _key_expansion(key_bytes)

        ciphertext = bytes.fromhex(cipher_hex)
        prev       = iv
        decrypted  = b""
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            dec   = _aes_decrypt_block(block, round_keys, nr)
            decrypted += bytes(a^b for a,b in zip(dec, prev))
            prev  = block

        plaintext = _pkcs7_unpad(decrypted).decode(errors="replace")
        return {"plaintext": plaintext}

    else:
        raise ValueError(f"Unknown operation '{operation}' for AES.")

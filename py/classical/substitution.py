import string
from collections import Counter

# English letter frequency order (most → least common)
ENGLISH_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


def _build_maps(key: str):
    """Return (enc_map, dec_map) dicts from a 26-letter key string."""
    key = key.upper().replace(" ", "")
    if len(key) != 26 or len(set(key)) != 26:
        raise ValueError("Key must be a 26-letter permutation of the alphabet.")
    enc = {string.ascii_uppercase[i]: key[i] for i in range(26)}
    dec = {v: k for k, v in enc.items()}
    return enc, dec


def _apply_map(text: str, mp: dict) -> str:
    result = []
    for ch in text.upper():
        result.append(mp.get(ch, ch))
    return "".join(result)


def handle(operation: str, params: dict) -> dict:
    op = operation.lower()

    if op == "encrypt":
        plaintext = params.get("plaintext", "")
        key       = params.get("key", "")
        enc_map, _ = _build_maps(key)
        ciphertext = _apply_map(plaintext, enc_map)
        # Build readable key table (A→Q, B→W, …)
        key_table = "\n".join(
            f"{string.ascii_uppercase[i]} → {key.upper()[i]}"
            for i in range(26)
        )
        return {
            "ciphertext": ciphertext,
            "key_table":  key_table,
        }

    elif op == "decrypt":
        ciphertext = params.get("ciphertext", "")
        key        = params.get("key", "")
        _, dec_map = _build_maps(key)
        plaintext  = _apply_map(ciphertext, dec_map)
        return {"plaintext": plaintext}

    elif op == "brute":
        # Try all 26 Caesar-shift keys
        ciphertext = params.get("ciphertext", "").upper()
        results = []
        for shift in range(26):
            dec = {
                string.ascii_uppercase[(i + shift) % 26]: string.ascii_uppercase[i]
                for i in range(26)
            }
            candidate = _apply_map(ciphertext, dec)
            results.append(f"Shift {shift:2d}: {candidate}")
        return {"brute_force_results": "\n".join(results)}

    elif op == "frequency":
        ciphertext = params.get("ciphertext", "").upper()
        counts     = Counter(ch for ch in ciphertext if ch.isalpha())
        total      = sum(counts.values()) or 1

        # Sort ciphertext letters by frequency (most → least)
        sorted_cipher = [ch for ch, _ in counts.most_common()]

        # Map each cipher letter → guessed plaintext letter by English freq rank
        freq_map = {}
        for i, cipher_ch in enumerate(sorted_cipher):
            if i < len(ENGLISH_FREQ):
                freq_map[cipher_ch] = ENGLISH_FREQ[i]

        # Frequency table lines
        freq_table_lines = []
        for ch, cnt in counts.most_common():
            pct   = cnt / total * 100
            guess = freq_map.get(ch, "?")
            freq_table_lines.append(
                f"{ch}: {cnt:4d} ({pct:5.1f}%)  → guessed plaintext: {guess}"
            )

        # Suggested decryption using frequency mapping
        suggested = "".join(freq_map.get(ch, ch) for ch in ciphertext)

        return {
            "frequency_table":       "\n".join(freq_table_lines),
            "suggested_plaintext":   suggested,
            "cipher_to_plain_guess": str(freq_map),
        }

    else:
        raise ValueError(f"Unknown operation '{operation}' for substitution cipher.")

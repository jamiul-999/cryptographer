from collections import Counter


def _parse_key(key: str) -> list[int]:
    """
    Convert a keyword or numeric list to a 0-indexed reading order.
    Keyword: sorted by alphabetical rank — e.g. "CAB" → [1, 2, 0]
    Numeric: "3,1,2" → [2, 0, 1] (0-indexed)
    """
    key = key.strip()
    if "," in key:
        parts = [int(x.strip()) for x in key.split(",")]
        order = [p - 1 for p in parts]
        seen: set[int] = set()
        for v in order:
            if v < 0 or v >= len(order):
                raise ValueError(f"Index {v + 1} out of range (key length {len(order)})")
            if v in seen:
                raise ValueError(f"Duplicate index {v + 1}")
            seen.add(v)
        return order
    else:
        letters = list(key.upper())
        return sorted(range(len(letters)), key=lambda i: letters[i])


def _row_col_encrypt(text: str, row_order: list[int], col_order: list[int]) -> tuple[str, str]:
    """
    Fill grid row-by-row, permute rows then columns, read row-by-row.
    Returns (after_row_perm, ciphertext).
    """
    n_rows = len(row_order)
    n_cols = len(col_order)

    grid = [list(text[r * n_cols:(r + 1) * n_cols]) for r in range(n_rows)]

    # Step 1: permute rows
    row_permed = [grid[row_order[i]] for i in range(n_rows)]

    after_row_perm = "".join("".join(row) for row in row_permed)

    # Step 2: permute columns
    cipher = "".join(row_permed[r][c] for r in range(n_rows) for c in col_order)

    return after_row_perm, cipher


def _row_col_decrypt(text: str, row_order: list[int], col_order: list[int]) -> tuple[str, str]:
    """
    Reverse _row_col_encrypt using inverse permutations.
    Returns (after_col_restore, plaintext).
    """
    n_rows = len(row_order)
    n_cols = len(col_order)

    c_grid = [list(text[r * n_cols:(r + 1) * n_cols]) for r in range(n_rows)]

    # Inverse column permutation: restore rowPermed state
    inv_col_grid = [[""] * n_cols for _ in range(n_rows)]
    for r in range(n_rows):
        for j, c in enumerate(col_order):
            inv_col_grid[r][c] = c_grid[r][j]

    after_col_restore = "".join("".join(row) for row in inv_col_grid)

    # Inverse row permutation: row_order[i]=r means inv_row[r]=i
    inv_row = [0] * n_rows
    for i, r in enumerate(row_order):
        inv_row[r] = i

    plain = "".join("".join(inv_col_grid[inv_row[r]]) for r in range(n_rows))
    return after_col_restore, plain


def handle(operation: str, params: dict) -> dict:
    op = operation.lower()

    if op == "encrypt":
        # Replace spaces with X so word boundaries survive encryption.
        plaintext    = params.get("plaintext", "").upper()
        plaintext    = plaintext.strip().replace(" ", "X")
        original_len = len(plaintext)
        key1         = params.get("key1", "")
        key2         = params.get("key2", "")

        row_order = _parse_key(key1)
        col_order = _parse_key(key2)

        n_rows = len(row_order)
        n_cols = len(col_order)
        total  = n_rows * n_cols

        if original_len > total:
            raise ValueError(
                f"Plaintext ({original_len} chars) exceeds grid capacity "
                f"{n_rows}×{n_cols}={total}; use longer keys."
            )

        # Pad to fill grid exactly.
        plaintext = plaintext.ljust(total, "X")

        after_row_perm, cipher = _row_col_encrypt(plaintext, row_order, col_order)

        return {
            "after_row_permutation": after_row_perm,
            "ciphertext":            cipher,
            "key1_order":            str([i + 1 for i in row_order]),
            "key2_order":            str([i + 1 for i in col_order]),
            "original_length":       str(original_len),
            "grid_size":             f"{n_rows} rows × {n_cols} cols",
        }

    elif op == "decrypt":
        ciphertext = params.get("ciphertext", "").upper()
        key1       = params.get("key1", "")
        key2       = params.get("key2", "")

        row_order = _parse_key(key1)
        col_order = _parse_key(key2)

        n_rows = len(row_order)
        n_cols = len(col_order)
        expected = n_rows * n_cols
        if len(ciphertext) != expected:
            raise ValueError(
                f"Ciphertext length {len(ciphertext)} does not match grid "
                f"{n_rows}×{n_cols}={expected}"
            )

        after_col_restore, plain = _row_col_decrypt(ciphertext, row_order, col_order)

        # Exact-length trim preferred to avoid eating real trailing X's.
        orig_len_str = params.get("original_length", "").strip()
        if orig_len_str:
            try:
                orig_len = int(orig_len_str)
                if 0 <= orig_len <= len(plain):
                    stripped     = plain[:orig_len]
                    padding_note = (f"exact trim to original length {orig_len} "
                                    f"(removed {len(plain) - orig_len} pad chars)")
                else:
                    stripped     = plain
                    padding_note = "original_length out of range; no trimming applied"
            except ValueError:
                stripped     = plain
                padding_note = "original_length invalid; no trimming applied"
        else:
            stripped     = plain.rstrip("X")
            padding_note = (f"heuristic trim (no original_length supplied): "
                            f"removed {len(plain) - len(stripped)} trailing X chars")

        return {
            "after_col_restore": after_col_restore,
            "plaintext":         stripped,
            "padding_note":      padding_note,
        }

    elif op == "frequency":
        ciphertext = params.get("ciphertext", "").upper()
        counts     = Counter(ch for ch in ciphertext if ch.isalpha())
        total      = sum(counts.values())
        if total == 0:
            raise ValueError("No alphabetic characters in ciphertext.")

        # English letter frequency order and reference percentages.
        english_order = list("ETAOINSHRDLCUMWFGYPBVKJXQZ")
        english_freq  = {
            'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
            'N': 6.75,  'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
            'L': 4.03,  'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
            'F': 2.23,  'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
            'V': 0.98,  'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
            'Z': 0.07,
        }

        ranked = counts.most_common()

        # Frequency table with English comparison.
        table_lines = ["Letter  Count   Cipher%   English%",
                       "------  -----  --------  ---------"]
        for ch, cnt in ranked:
            pct = cnt / total * 100
            eng = english_freq.get(ch, 0.0)
            table_lines.append(f"  {ch}     {cnt:4d}    {pct:5.1f}%    {eng:5.2f}%")

        # Index of Coincidence.
        ioc = (sum(c * (c - 1) for c in counts.values()) /
               (total * (total - 1))) if total > 1 else 0.0
        if ioc >= 0.060:
            ioc_note = " (≈ English — likely transposition or mono-alphabetic substitution)"
        elif ioc >= 0.045:
            ioc_note = " (moderate — possibly short Vigenère or polyalphabetic)"
        else:
            ioc_note = " (low — likely polyalphabetic / random)"

        # Frequency-mapping guess: map cipher's top-N to English's top-N.
        mapping = {ch: english_order[i] for i, (ch, _) in enumerate(ranked)
                   if i < len(english_order)}
        guessed = "".join(mapping.get(ch, ch) for ch in ciphertext if ch.isalpha())

        # Mapping legend.
        legend_lines = ["Cipher → Guess (by frequency rank)"]
        for i, (ch, _) in enumerate(ranked):
            if i >= len(english_order):
                break
            legend_lines.append(f"  {ch} → {english_order[i]}")

        return {
            "frequency_table":   "\n".join(table_lines),
            "ioc":               f"{ioc:.4f}{ioc_note}",
            "mapping_legend":    "\n".join(legend_lines),
            "guessed_plaintext": guessed,
            "note": (
                "For transposition ciphers letter frequencies are preserved from the "
                "plaintext. A high IoC (≥0.060) confirms transposition. The guessed "
                "plaintext applies a simple frequency substitution — it is useful mainly "
                "for mono-alphabetic substitution ciphers, not pure transposition."
            ),
        }

    else:
        raise ValueError(f"Unknown operation '{operation}' for double transposition.")

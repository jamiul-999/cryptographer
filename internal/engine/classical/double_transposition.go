package classical

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func DoubleTransposition(operation string, params map[string]string) (map[string]string, error) {
	op := strings.ToLower(operation)

	switch op {
	case "encrypt":
		// Replace spaces with X (spaces become visible in decrypted output as X).
		plaintext := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(params["plaintext"]), " ", "X"))
		originalLen := len(plaintext) // before padding

		rowOrder, err := parseKey(params["key1"])
		if err != nil {
			return nil, fmt.Errorf("key1: %w", err)
		}
		colOrder, err := parseKey(params["key2"])
		if err != nil {
			return nil, fmt.Errorf("key2: %w", err)
		}

		nRows := len(rowOrder)
		nCols := len(colOrder)
		total := nRows * nCols

		if originalLen > total {
			return nil, fmt.Errorf(
				"plaintext (%d chars) exceeds grid capacity %d×%d=%d; use longer keys",
				originalLen, nRows, nCols, total)
		}

		// Pad to fill grid exactly.
		if originalLen < total {
			plaintext += strings.Repeat("X", total-originalLen)
		}

		afterRowPerm, cipher := rowColEncrypt(plaintext, rowOrder, colOrder)

		return map[string]string{
			"after_row_permutation": afterRowPerm,
			"ciphertext":            cipher,
			"key1_order":            formatOrder(rowOrder),
			"key2_order":            formatOrder(colOrder),
			"original_length":       strconv.Itoa(originalLen),
			"grid_size":             fmt.Sprintf("%d rows × %d cols", nRows, nCols),
		}, nil

	case "decrypt":
		ciphertext := strings.ToUpper(params["ciphertext"])
		rowOrder, err := parseKey(params["key1"])
		if err != nil {
			return nil, fmt.Errorf("key1: %w", err)
		}
		colOrder, err := parseKey(params["key2"])
		if err != nil {
			return nil, fmt.Errorf("key2: %w", err)
		}

		nRows := len(rowOrder)
		nCols := len(colOrder)
		if len(ciphertext) != nRows*nCols {
			return nil, fmt.Errorf(
				"ciphertext length %d does not match grid %d×%d=%d",
				len(ciphertext), nRows, nCols, nRows*nCols)
		}

		afterColRestore, plain := rowColDecrypt(ciphertext, rowOrder, colOrder)

		// Trim padding: exact slice preferred to avoid eating real trailing X's.
		var stripped, paddingNote string
		if s := strings.TrimSpace(params["original_length"]); s != "" {
			origLen, err := strconv.Atoi(s)
			if err == nil && origLen >= 0 && origLen <= len(plain) {
				stripped = plain[:origLen]
				paddingNote = fmt.Sprintf("exact trim to original length %d (removed %d pad chars)", origLen, len(plain)-origLen)
			} else {
				stripped = plain
				paddingNote = "original_length invalid or out of range; no trimming applied"
			}
		} else {
			stripped = strings.TrimRight(plain, "X")
			paddingNote = fmt.Sprintf("heuristic trim (no original_length supplied): removed %d trailing X chars", len(plain)-len(stripped))
		}

		return map[string]string{
			"after_col_restore": afterColRestore,
			"plaintext":         stripped,
			"padding_note":      paddingNote,
		}, nil

	case "frequency":
		ciphertext := strings.ToUpper(params["ciphertext"])
		counts := make(map[rune]int)
		total := 0
		for _, ch := range ciphertext {
			if ch >= 'A' && ch <= 'Z' {
				counts[ch]++
				total++
			}
		}
		if total == 0 {
			return nil, fmt.Errorf("no alphabetic characters in ciphertext")
		}

		// English letter frequency order (most→least common).
		englishOrder := []rune("ETAOINSHRDLCUMWFGYPBVKJXQZ")

		type pair struct {
			ch  rune
			cnt int
		}
		var pairs []pair
		for ch, cnt := range counts {
			pairs = append(pairs, pair{ch, cnt})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].cnt > pairs[j].cnt })

		// English reference frequencies (%).
		englishFreq := map[rune]float64{
			'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
			'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
			'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
			'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
			'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
			'Z': 0.07,
		}

		// Frequency table with English comparison.
		var tableLines strings.Builder
		tableLines.WriteString("Letter  Count   Cipher%   English%\n")
		tableLines.WriteString("------  -----  --------  ---------\n")
		for _, p := range pairs {
			pct := float64(p.cnt) / float64(total) * 100
			eng := englishFreq[p.ch]
			tableLines.WriteString(fmt.Sprintf("  %c     %4d    %5.1f%%    %5.2f%%\n", p.ch, p.cnt, pct, eng))
		}

		// Index of Coincidence (IoC). English prose ≈ 0.065; random ≈ 0.038.
		ioc := 0.0
		if total > 1 {
			for _, cnt := range counts {
				ioc += float64(cnt) * float64(cnt-1)
			}
			ioc /= float64(total) * float64(total-1)
		}
		ioStr := fmt.Sprintf("%.4f", ioc)
		ioNote := ""
		switch {
		case ioc >= 0.060:
			ioNote = " (≈ English — likely transposition or mono-alphabetic substitution)"
		case ioc >= 0.045:
			ioNote = " (moderate — possibly short Vigenère or polyalphabetic)"
		default:
			ioNote = " (low — likely polyalphabetic / random)"
		}

		// Frequency-mapping guess: map ciphertext's top-N letters to English's top-N.
		// For a transposition cipher this is a no-op (frequencies are preserved),
		// but it gives a rough plaintext guess for substitution-like analysis.
		mapping := make(map[rune]rune)
		for i, p := range pairs {
			if i >= len(englishOrder) {
				break
			}
			mapping[p.ch] = englishOrder[i]
		}
		var guessed strings.Builder
		for _, ch := range ciphertext {
			if ch >= 'A' && ch <= 'Z' {
				if mapped, ok := mapping[ch]; ok {
					guessed.WriteRune(mapped)
				} else {
					guessed.WriteRune(ch)
				}
			}
		}

		// Build mapping legend.
		var legendLines strings.Builder
		legendLines.WriteString("Cipher → Guess (by frequency rank)\n")
		for i, p := range pairs {
			if i >= len(englishOrder) {
				break
			}
			legendLines.WriteString(fmt.Sprintf("  %c → %c\n", p.ch, englishOrder[i]))
		}

		return map[string]string{
			"frequency_table":   strings.TrimRight(tableLines.String(), "\n"),
			"ioc":               ioStr + ioNote,
			"mapping_legend":    strings.TrimRight(legendLines.String(), "\n"),
			"guessed_plaintext": guessed.String(),
			"note": "For transposition ciphers letter frequencies are preserved from the " +
				"plaintext. A high IoC (≥0.060) confirms transposition. The guessed plaintext " +
				"applies a simple frequency substitution — it is useful mainly for mono-alphabetic " +
				"substitution ciphers, not pure transposition.",
		}, nil

	default:
		return nil, fmt.Errorf("unknown operation %q for double transposition", operation)
	}
}

// rowColEncrypt fills a grid row-by-row, permutes rows then columns, reads row-by-row.
// Returns (afterRowPerm, ciphertext).
func rowColEncrypt(text string, rowOrder, colOrder []int) (string, string) {
	nRows := len(rowOrder)
	nCols := len(colOrder)
	runes := []rune(text)

	// Original grid
	grid := make([][]rune, nRows)
	for r := 0; r < nRows; r++ {
		grid[r] = runes[r*nCols : (r+1)*nCols]
	}

	// Step 1: permute rows — new_grid[i] = grid[rowOrder[i]]
	rowPermed := make([][]rune, nRows)
	for i, r := range rowOrder {
		rowPermed[i] = grid[r]
	}

	// Intermediate: read row-permed grid row by row
	var sbMid strings.Builder
	for _, row := range rowPermed {
		sbMid.WriteString(string(row))
	}

	// Step 2: permute columns — cipher[r][j] = rowPermed[r][colOrder[j]]
	var sbOut strings.Builder
	for r := 0; r < nRows; r++ {
		for _, c := range colOrder {
			sbOut.WriteRune(rowPermed[r][c])
		}
	}

	return sbMid.String(), sbOut.String()
}

// rowColDecrypt reverses rowColEncrypt using inverse permutations.
// Returns (afterColRestore, plaintext).
func rowColDecrypt(text string, rowOrder, colOrder []int) (string, string) {
	nRows := len(rowOrder)
	nCols := len(colOrder)
	runes := []rune(text)

	// Fill cipher grid row by row
	cGrid := make([][]rune, nRows)
	for r := 0; r < nRows; r++ {
		cGrid[r] = runes[r*nCols : (r+1)*nCols]
	}

	// Inverse column permutation: colOrder[j]=c means col j of result came from col c of input.
	// Restore: rowPermed[r][colOrder[j]] = cGrid[r][j]
	invCol := make([][]rune, nRows)
	for r := 0; r < nRows; r++ {
		invCol[r] = make([]rune, nCols)
		for j, c := range colOrder {
			invCol[r][c] = cGrid[r][j]
		}
	}

	// Intermediate: after restoring columns (= after-row-perm state)
	var sbMid strings.Builder
	for _, row := range invCol {
		sbMid.WriteString(string(row))
	}

	// Inverse row permutation: rowOrder[i]=r means row i of rowPermed came from row r of original.
	// Restore: grid[rowOrder[i]] = rowPermed[i] → grid[r] = invCol[invRow[r]]
	invRow := make([]int, nRows)
	for i, r := range rowOrder {
		invRow[r] = i
	}

	var sbOut strings.Builder
	for r := 0; r < nRows; r++ {
		sbOut.WriteString(string(invCol[invRow[r]]))
	}

	return sbMid.String(), sbOut.String()
}

// parseKey converts a keyword (e.g. "KEY") or numeric list (e.g. "3,1,2") to 0-indexed reading order.
// For a keyword the result is indices sorted by alphabetical rank of each letter.
// E.g. "CAB" → C=rank2, A=rank0, B=rank1 → reading order [1, 2, 0].
func parseKey(key string) ([]int, error) {
	key = strings.TrimSpace(key)
	if strings.Contains(key, ",") {
		parts := strings.Split(key, ",")
		order := make([]int, len(parts))
		for i, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				return nil, fmt.Errorf("invalid numeric key segment %q", p)
			}
			order[i] = n - 1
		}
		seen := make(map[int]bool)
		for _, v := range order {
			if v < 0 || v >= len(order) {
				return nil, fmt.Errorf("index %d out of range (key length %d)", v+1, len(order))
			}
			if seen[v] {
				return nil, fmt.Errorf("duplicate index %d", v+1)
			}
			seen[v] = true
		}
		return order, nil
	}

	letters := []rune(strings.ToUpper(key))
	n := len(letters)
	temp := make([]rune, n)
	copy(temp, letters)
	sort.Slice(temp, func(i, j int) bool { return temp[i] < temp[j] })

	used := make([]bool, n)
	rankOf := make([]int, n)
	for i, ch := range temp {
		for j, orig := range letters {
			if orig == ch && !used[j] {
				rankOf[j] = i
				used[j] = true
				break
			}
		}
	}
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(i, j int) bool { return rankOf[indices[i]] < rankOf[indices[j]] })
	return indices, nil
}

func formatOrder(order []int) string {
	parts := make([]string, len(order))
	for i, v := range order {
		parts[i] = strconv.Itoa(v + 1)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

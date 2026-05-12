// Package classical implements classical cryptographic algorithms in Go.
package classical

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// englishFreq is the standard English letter frequency order (most → least).
const englishFreq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

// Substitution handles encrypt / decrypt / frequency operations
// for the monoalphabetic substitution cipher.
func Substitution(operation string, params map[string]string) (map[string]string, error) {
	op := strings.ToLower(operation)

	switch op {
	case "encrypt":
		plaintext := strings.ToUpper(params["plaintext"])
		key := strings.ToUpper(strings.ReplaceAll(params["key"], " ", ""))
		if len(key) != 26 {
			return nil, fmt.Errorf("key must be exactly 26 letters, got %d", len(key))
		}
		encMap := buildEncMap(key)
		ciphertext := applyMap(plaintext, encMap)
		return map[string]string{
			"ciphertext": ciphertext,
			"key_table":  buildKeyTable(key),
		}, nil

	case "decrypt":
		ciphertext := strings.ToUpper(params["ciphertext"])
		key := strings.ToUpper(strings.ReplaceAll(params["key"], " ", ""))
		if len(key) != 26 {
			return nil, fmt.Errorf("key must be exactly 26 letters, got %d", len(key))
		}
		decMap := buildDecMap(key)
		return map[string]string{"plaintext": applyMap(ciphertext, decMap)}, nil

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

		type pair struct {
			ch  rune
			cnt int
		}
		var pairs []pair
		for ch, cnt := range counts {
			pairs = append(pairs, pair{ch, cnt})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].cnt > pairs[j].cnt })

		freqMap := make(map[rune]rune)
		for i, p := range pairs {
			if i < len(englishFreq) {
				freqMap[p.ch] = rune(englishFreq[i])
			}
		}

		var tableLines, suggested strings.Builder
		for _, p := range pairs {
			pct := float64(p.cnt) / float64(total) * 100
			guess, _ := freqMap[p.ch]
			tableLines.WriteString(fmt.Sprintf("%c: %4d (%5.1f%%)  → guessed plaintext: %c\n", p.ch, p.cnt, pct, guess))
		}
		for _, ch := range ciphertext {
			if g, ok := freqMap[ch]; ok {
				suggested.WriteRune(g)
			} else if unicode.IsLetter(ch) {
				suggested.WriteRune(ch)
			} else {
				suggested.WriteRune(ch)
			}
		}
		return map[string]string{
			"frequency_table":     strings.TrimRight(tableLines.String(), "\n"),
			"suggested_plaintext": suggested.String(),
		}, nil

	default:
		return nil, fmt.Errorf("unknown operation %q for substitution cipher", operation)
	}
}

func buildEncMap(key string) map[rune]rune {
	m := make(map[rune]rune, 26)
	for i, ch := range key {
		m[rune('A'+i)] = ch
	}
	return m
}

func buildDecMap(key string) map[rune]rune {
	m := make(map[rune]rune, 26)
	for i, ch := range key {
		m[ch] = rune('A' + i)
	}
	return m
}

func applyMap(text string, mp map[rune]rune) string {
	var sb strings.Builder
	for _, ch := range text {
		if mapped, ok := mp[ch]; ok {
			sb.WriteRune(mapped)
		} else {
			sb.WriteRune(ch)
		}
	}
	return sb.String()
}

func buildKeyTable(key string) string {
	var sb strings.Builder
	for i, ch := range key {
		sb.WriteString(fmt.Sprintf("%c → %c\n", 'A'+i, ch))
	}
	return strings.TrimRight(sb.String(), "\n")
}

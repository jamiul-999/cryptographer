package views

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"cryptographer/internal/models"
	"cryptographer/internal/tui/components"
	"cryptographer/internal/tui/styles"
)

// ResultPanelModel holds one or two results for display.
type ResultPanelModel struct {
	Primary          models.AlgoResult
	Secondary        *models.AlgoResult // non-nil in comparison mode
	BenchmarkResults []models.AlgoResult // non-nil for full symmetric benchmark
	BenchmarkHeaders []string
	Width            int
	Height           int
	ScrollY          int
}

func NewResultPanel(w, h int) ResultPanelModel {
	return ResultPanelModel{Width: w, Height: h}
}

func (m ResultPanelModel) SetResults(primary models.AlgoResult, secondary *models.AlgoResult) ResultPanelModel {
	m.Primary = primary
	m.Secondary = secondary
	m.BenchmarkResults = nil
	m.BenchmarkHeaders = nil
	m.ScrollY = 0
	return m
}

func (m ResultPanelModel) SetBenchmarkResults(results []models.AlgoResult, headers []string) ResultPanelModel {
	m.BenchmarkResults = results
	m.BenchmarkHeaders = headers
	m.Secondary = nil
	m.ScrollY = 0
	return m
}

func (m ResultPanelModel) ScrollDown() ResultPanelModel {
	m.ScrollY++
	return m
}
func (m ResultPanelModel) ScrollUp() ResultPanelModel {
	if m.ScrollY > 0 { m.ScrollY-- }
	return m
}

// View renders the result panel.
func (m ResultPanelModel) View() string {
	var content string

	if len(m.BenchmarkResults) > 0 {
		content = components.BenchmarkTable(m.BenchmarkResults, m.BenchmarkHeaders, m.Width-4)
	} else if m.Secondary != nil {
		// Comparison mode: side-by-side
		content = components.ComparisonTable(m.Primary, *m.Secondary, m.Width-4)
	} else {
		content = m.renderSingle(m.Primary)
	}

	// Apply scroll
	lines := strings.Split(content, "\n")
	if m.ScrollY < len(lines) {
		lines = lines[m.ScrollY:]
	}
	visible := m.Height - 6
	if visible < 1 { visible = 1 }
	if len(lines) > visible {
		lines = lines[:visible]
	}
	scrolled := strings.Join(lines, "\n")

	var hint string
	if len(m.BenchmarkResults) > 0 {
		hint = styles.Muted.Render("  ↑↓ scroll  [benchmark mode]")
	} else {
		hint = styles.Muted.Render(fmt.Sprintf("  ↑↓ scroll  [backend: %s]  %.2fms",
			m.Primary.Backend, m.Primary.ElapsedMs))
	}

	return styles.BorderAccent.
		Width(m.Width - 2).
		Height(m.Height - 2).
		Render(
			lipgloss.JoinVertical(lipgloss.Left,
				styles.Title.Render("  Output"),
				"",
				scrolled,
				"",
				hint,
			),
		)
}

func (m ResultPanelModel) renderSingle(res models.AlgoResult) string {
	if res.Error != "" {
		return styles.Error.Render("  ✗ Error\n\n  " + res.Error)
	}
	if len(res.Output) == 0 {
		return styles.Muted.Render("  No output yet. Run an operation to see results here.")
	}

	var sb strings.Builder
	
	// Map internal keys to requirement output keys
	reqMap := map[string]string{
		"ciphertext":          "Ciphertext",
		"ciphertext_int":      "Ciphertext (as integer)",
		"ciphertext_hex":      "Ciphertext (as hex)",
		"plaintext":           "Original plaintext",
		"suggested_plaintext": "Original plaintext",
		"frequency_table":     "Result of the frequency analysis",
		"key_table":           "Result of the frequency analysis",
		"key_hex":             "Key",
		"round_keys":          "All round keys",
		"public_key_n":        "Public key (n)",
		"public_key_e":        "Public key (e)",
		"private_key_d":       "Private key",
		"private_key":         "Private key",
		"points":              "List of all Ps",
		"shared_secret_x":     "Shared key (x)",
		"shared_secret_y":     "Shared key (y)",
		"factor_p":            "Result of Factorization attack",
		"factor_q":            "Result of Factorization attack",
	}

	if res.Algorithm == "rsa" && res.Operation == "decrypt" {
		reqMap["plaintext"] = "Decrypted message"
	}
	if res.Algorithm == "double_transposition" && res.Operation == "encrypt" {
		reqMap["ciphertext"] = "Permuted ciphertext"
	}

	priority := []string{"Ciphertext", "Permuted ciphertext", "Original plaintext", "Ciphertext (as integer)", "Ciphertext (as hex)", "Decrypted message", "Result of the frequency analysis", "Key", "All round keys", "Public key (n)", "Public key (e)", "Private key", "List of all Ps", "Shared key (x)", "Shared key (y)", "Result of Factorization attack"}

	// Build a mapped output
	mappedOut := make(map[string]string)
	for k, v := range res.Output {
		if mapped, ok := reqMap[k]; ok {
			if existing, exists := mappedOut[mapped]; exists {
				mappedOut[mapped] = existing + "\n" + v
			} else {
				mappedOut[mapped] = v
			}
		} else {
			mappedOut[k] = v
		}
	}

	printed := map[string]bool{}
	for _, k := range priority {
		if v, ok := mappedOut[k]; ok {
			sb.WriteString(renderKV(k, v, m.Width-8))
			printed[k] = true
		}
	}
	for k, v := range mappedOut {
		if !printed[k] {
			sb.WriteString(renderKV(k, v, m.Width-8))
		}
	}
	return sb.String()
}

func renderKV(key, value string, maxW int) string {
	label := styles.Label.Render("  " + key + ":")
	lines := strings.Split(value, "\n")
	var vLines []string
	for _, l := range lines {
		vLines = append(vLines, "    "+l)
	}
	val := styles.Value.Render(strings.Join(vLines, "\n"))
	return label + "\n" + val + "\n\n"
}

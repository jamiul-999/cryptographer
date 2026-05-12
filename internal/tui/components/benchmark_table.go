package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"cryptographer/internal/models"
)

// BenchmarkTable renders a dynamic benchmark table for N columns.
func BenchmarkTable(results []models.AlgoResult, headers []string, width int) string {
	if len(results) == 0 {
		return ""
	}

	nCols := len(results)

	// Determine how many columns we can fit
	colW := make([]int, nCols+1)
	colW[0] = 15 // Label column

	totalWidth := colW[0] + 1 // +1 for left border
	visibleCols := 0
	for i := 0; i < nCols; i++ {
		w := len(headers[i]) + 2
		if w < 12 {
			w = 12
		}
		if totalWidth+w+1 > width {
			break
		}
		colW[i+1] = w
		totalWidth += w + 1
		visibleCols++
	}

	if visibleCols == 0 {
		return "Terminal too narrow."
	}

	results = results[:visibleCols]
	headers = headers[:visibleCols]
	nCols = visibleCols
	colW = colW[:nCols+1]

	ciphers := make([]string, nCols)
	timeStr := make([]string, nCols)
	keySize := make([]string, nCols)
	blockSize := make([]string, nCols)
	rounds := make([]string, nCols)
	speedBar := make([]string, nCols)

	maxTime := 0.0
	for _, r := range results {
		if r.ElapsedMs > maxTime {
			maxTime = r.ElapsedMs
		}
	}
	if maxTime == 0 {
		maxTime = 1
	}

	for i, r := range results {
		ciphers[i] = shorten(r.Output["ciphertext"], 12)

		timeStr[i] = fmt.Sprintf("%.2fms", r.ElapsedMs)

		// Set defaults for known symmetric
		defKS := "N/A"
		defBS := "N/A"
		defR := "N/A"

		if r.Algorithm == "des" {
			defKS = "56-bit"
			defBS = "64-bit"
			defR = "16"
		} else if r.Algorithm == "aes" {
			defKS = "128-bit"
			defBS = "128-bit"
			defR = "10"
		}

		keySize[i] = def(r.Output["key_size"], defKS)
		blockSize[i] = def(r.Output["block_size"], defBS)
		rounds[i] = def(r.Output["rounds"], defR)
		speedBar[i] = renderBar(r.ElapsedMs, maxTime)
	}



	var sb strings.Builder

	// Top border
	sb.WriteString("┌" + strings.Repeat("─", colW[0]))
	for i := 1; i <= nCols; i++ {
		sb.WriteString("┬" + strings.Repeat("─", colW[i]))
	}
	sb.WriteString("┐\n")

	// Headers
	sb.WriteString(row(colW, append([]string{""}, headers...)...) + "\n")

	// Divider
	sb.WriteString("├" + strings.Repeat("─", colW[0]))
	for i := 1; i <= nCols; i++ {
		sb.WriteString("┼" + strings.Repeat("─", colW[i]))
	}
	sb.WriteString("┤\n")

	// Rows
	sb.WriteString(row(colW, append([]string{"Ciphertext"}, ciphers...)...) + "\n")
	sb.WriteString(row(colW, append([]string{"Time"}, timeStr...)...) + "\n")
	sb.WriteString(row(colW, append([]string{"Key size"}, keySize...)...) + "\n")
	sb.WriteString(row(colW, append([]string{"Block size"}, blockSize...)...) + "\n")
	sb.WriteString(row(colW, append([]string{"Rounds"}, rounds...)...) + "\n")
	sb.WriteString(row(colW, append([]string{"Speed bar"}, speedBar...)...) + "\n")

	// Bottom border
	sb.WriteString("└" + strings.Repeat("─", colW[0]))
	for i := 1; i <= nCols; i++ {
		sb.WriteString("┴" + strings.Repeat("─", colW[i]))
	}
	sb.WriteString("┘\n")
	
	origLen := len(timeStr)
	
	if visibleCols < origLen {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000")).Render("  * Some columns hidden (terminal too narrow)"))
	}

	return lipgloss.NewStyle().Padding(0, 0).Render(sb.String())
}

func row(widths []int, cols ...string) string {
	var sb strings.Builder
	sb.WriteString("│")
	for i, c := range cols {
		w := 14
		if i < len(widths) {
			w = widths[i]
		}
		spaces := w - lipgloss.Width(c) - 1
		if spaces < 0 {
			spaces = 0
		}
		sb.WriteString(" " + c + strings.Repeat(" ", spaces) + "│")
	}
	return sb.String()
}

func shorten(s string, l int) string {
	if len(s) > l {
		return s[:l-3] + "..."
	}
	if len(s) == 0 {
		return "N/A"
	}
	return s
}

func def(s, d string) string {
	if s == "" {
		return d
	}
	return s
}


func renderBar(val, max float64) string {
	if val < 0 { val = 0 }
	ratio := val / max
	totalBlocks := 8
	filled := int(ratio * float64(totalBlocks))
	if filled == 0 && val > 0 { filled = 1 }
	if filled > totalBlocks { filled = totalBlocks }
	empty := totalBlocks - filled

	fStr := strings.Repeat("█", filled)
	eStr := strings.Repeat("░", empty)
	
	col := "#00ff00" // fast
	if ratio > 0.5 { col = "#ffff00" }
	if ratio > 0.8 { col = "#ff0000" }
	
	return lipgloss.NewStyle().Foreground(lipgloss.Color(col)).Render(fStr) + lipgloss.NewStyle().Foreground(lipgloss.Color("#555555")).Render(eStr)
}

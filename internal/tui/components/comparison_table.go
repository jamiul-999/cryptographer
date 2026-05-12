package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"cryptographer/internal/models"
	"cryptographer/internal/tui/styles"
)

// ComparisonTable renders a side-by-side Go vs Python result table.
func ComparisonTable(goRes, pyRes models.AlgoResult, width int) string {
	half := (width - 5) / 2

	goHeader := lipgloss.NewStyle().Foreground(lipgloss.Color("#58a6ff")).Bold(true).Render("⚙  Go Backend")
	pyHeader := lipgloss.NewStyle().Foreground(styles.ColorAccent).Bold(true).Render("🐍 Python Backend")

	goTime := styles.Muted.Render(fmt.Sprintf("%.2fms", goRes.ElapsedMs))
	pyTime := styles.Muted.Render(fmt.Sprintf("%.2fms", pyRes.ElapsedMs))

	goBody := renderOutput(goRes, half-4)
	pyBody := renderOutput(pyRes, half-4)

	goCol := styles.BorderNormal.Width(half).Padding(0, 1).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Center, goHeader, "  ", goTime),
			"",
			goBody,
		),
	)
	pyCol := styles.BorderNormal.Width(half).Padding(0, 1).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Center, pyHeader, "  ", pyTime),
			"",
			pyBody,
		),
	)

	return lipgloss.JoinHorizontal(lipgloss.Top, goCol, " ", pyCol)
}

func renderOutput(res models.AlgoResult, maxWidth int) string {
	if res.Error != "" {
		return styles.Error.Render("Error: " + res.Error)
	}
	var sb strings.Builder
	for k, v := range res.Output {
		key := styles.Label.Render(k + ":")
		val := truncate(v, maxWidth-len(k)-3)
		sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, key, " ", styles.Value.Render(val)))
		sb.WriteString("\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func truncate(s string, max int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > 6 {
		lines = append(lines[:6], "  ...")
	}
	result := strings.Join(lines, "\n")
	if len(result) > max && max > 3 {
		return result[:max-3] + "..."
	}
	return result
}

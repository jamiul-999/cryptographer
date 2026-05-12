package components

import (
	"fmt"

	"cryptographer/internal/tui/styles"

	"github.com/charmbracelet/lipgloss"
)

// Header renders the top bar with app name, clock, and backend indicator.
func Header(width int, backend string) string {
	left := styles.Title.Render("⚡ Cryptographer v1.0")

	var backendColor lipgloss.Color
	switch backend {
	case "go":
		backendColor = lipgloss.Color("#58a6ff")
	case "both":
		backendColor = lipgloss.Color("#f0883e")
	default:
		backendColor = styles.ColorAccent
	}
	backendBadge := lipgloss.NewStyle().
		Foreground(backendColor).Bold(true).Render(fmt.Sprintf("[%s]", backend))

	right := backendBadge

	gap := width - lipgloss.Width(left) - lipgloss.Width(right) - 4
	if gap < 0 {
		gap = 0
	}
	spacer := lipgloss.NewStyle().Width(gap).Render("")

	bar := lipgloss.JoinHorizontal(lipgloss.Center, left, spacer, right)
	return styles.Header.Width(width).Render(bar)
}

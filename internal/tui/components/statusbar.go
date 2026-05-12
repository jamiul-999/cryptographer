package components

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"cryptographer/internal/tui/styles"
)

// StatusBar renders the bottom bar with mode, hint, and timing.
func StatusBar(width int, mode, hint string, elapsedMs float64) string {
	left := styles.StatusBar.Render(fmt.Sprintf(" %s ", mode))

	right := ""
	if elapsedMs > 0 {
		right = styles.StatusBar.Foreground(styles.ColorAccent).Render(
			fmt.Sprintf(" %.2fms ", elapsedMs),
		)
	}

	hintStr := styles.StatusBar.Foreground(styles.ColorMuted).Render(fmt.Sprintf(" %s ", hint))

	gap := width - lipgloss.Width(left) - lipgloss.Width(hintStr) - lipgloss.Width(right)
	if gap < 0 { gap = 0 }
	spacer := styles.StatusBar.Width(gap).Render("")

	return lipgloss.JoinHorizontal(lipgloss.Bottom, left, spacer, hintStr, right)
}

package views

import (
	"cryptographer/internal/tui/styles"
	"strings"
)

// HelpView renders the keybindings overlay.
func HelpView(width int) string {
	bindings := [][2]string{
		{"↑", "Move up"},
		{"↓", "Move down"},
		{"Enter", "Select / Run"},
		{"Tab", "Next field"},
		{"Shift+Tab", "Previous field"},
		{"Esc", "Go back"},
		{"Ctrl+s", "Toggle settings"},
		{"F1", "Toggle this help"},
		{"↑↓ (result pane)", "Scroll output"},
		{"Ctrl+C", "Quit"},
	}

	var sb strings.Builder
	sb.WriteString(styles.Title.Render("  Keybindings") + "\n\n")
	for _, b := range bindings {
		key := styles.KeyHint.Render(b[0])
		desc := styles.Muted.Render("  " + b[1])
		sb.WriteString("  " + key + desc + "\n\n")
	}

	return styles.BorderFocused.
		Width(width/2).
		Padding(1, 2).
		Render(sb.String())
}

// OpSelectView renders a mini operation picker for the chosen algorithm.
func OpSelectView(algo AlgorithmEntry, selected int, w int) string {
	var sb strings.Builder
	sb.WriteString(styles.Title.Render("  Select Operation") + "\n\n")
	for i, op := range algo.Ops {
		line := "  " + strings.ToUpper(op)
		if i == selected {
			sb.WriteString(styles.Selected.Width(w-8).Render(line) + "\n")
		} else {
			sb.WriteString(styles.Unselected.Width(w-8).Render(line) + "\n")
		}
	}
	sb.WriteString("\n" + styles.Muted.Render("  Enter: confirm   Esc: back"))
	return styles.BorderNormal.Width(w/2).Padding(1, 2).Render(sb.String())
}

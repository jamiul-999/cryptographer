// Package styles defines the lip gloss color palette and component styles.
package styles

import "github.com/charmbracelet/lipgloss"

// Palette — dark hacker-green theme
var (
	ColorBg        = lipgloss.Color("#0d1117")
	ColorSurface   = lipgloss.Color("#161b22")
	ColorBorder    = lipgloss.Color("#30a46c")
	ColorAccent    = lipgloss.Color("#00e5a0")
	ColorAccent2   = lipgloss.Color("#58a6ff")
	ColorMuted     = lipgloss.Color("#8b949e")
	ColorFg        = lipgloss.Color("#e6edf3")
	ColorWarning   = lipgloss.Color("#f0883e")
	ColorError     = lipgloss.Color("#ff4c4c")
	ColorSuccess   = lipgloss.Color("#3fb950")
	ColorHighlight = lipgloss.Color("#1f6feb")
)

// Border styles
var (
	BorderNormal = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder)

	BorderAccent = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorAccent)

	BorderFocused = lipgloss.NewStyle().
			Border(lipgloss.ThickBorder()).
			BorderForeground(ColorAccent)
)

// Text styles
var (
	Title = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Bold(true).
		PaddingLeft(1)

	Subtitle = lipgloss.NewStyle().
			Foreground(ColorAccent2).
			Italic(true)

	Muted = lipgloss.NewStyle().
		Foreground(ColorMuted)

	Label = lipgloss.NewStyle().
		Foreground(ColorFg).
		Bold(true)

	Value = lipgloss.NewStyle().
		Foreground(ColorAccent)

	Error = lipgloss.NewStyle().
		Foreground(ColorError).
		Bold(true)

	Success = lipgloss.NewStyle().
		Foreground(ColorSuccess)

	Warning = lipgloss.NewStyle().
		Foreground(ColorWarning)

	KeyHint = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Background(lipgloss.Color("#1a2a1a")).
		Padding(0, 1)

	Selected = lipgloss.NewStyle().
			Foreground(ColorBg).
			Background(ColorAccent).
			Bold(true).
			PaddingLeft(1).
			PaddingRight(1)

	Unselected = lipgloss.NewStyle().
			Foreground(ColorFg).
			PaddingLeft(1).
			PaddingRight(1)
)

// Layout helpers
var (
	FullWidth = lipgloss.NewStyle().Width(0) // set width dynamically

	Panel = lipgloss.NewStyle().
		Background(ColorSurface).
		Padding(1, 2)

	StatusBar = lipgloss.NewStyle().
			Background(lipgloss.Color("#21262d")).
			Foreground(ColorMuted).
			Padding(0, 1)

	Header = lipgloss.NewStyle().
		Background(ColorBg).
		Foreground(ColorAccent).
		Bold(true).
		Padding(0, 2)
)

// Badge renders a small colored badge.
func Badge(text string, fg, bg lipgloss.Color) string {
	return lipgloss.NewStyle().
		Foreground(fg).
		Background(bg).
		Bold(true).
		Padding(0, 1).
		Render(text)
}

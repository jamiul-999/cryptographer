package views

import (
	"strings"

	"cryptographer/internal/config"
	"cryptographer/internal/tui/styles"
)

// SettingsModel holds the settings overlay state.
type SettingsModel struct {
	Cfg     *config.Config
	Focused int
	Width   int
	Height  int
}

var settingLabels = []string{"Backend", "Theme", "Python Bin", "Save & Close"}

func NewSettings(cfg *config.Config, w, h int) SettingsModel {
	return SettingsModel{Cfg: cfg, Width: w, Height: h}
}

func (m SettingsModel) MoveUp() SettingsModel {
	if m.Focused > 0 { m.Focused-- }
	return m
}
func (m SettingsModel) MoveDown() SettingsModel {
	if m.Focused < len(settingLabels)-1 { m.Focused++ }
	return m
}

// Toggle cycles the focused setting's value.
func (m SettingsModel) Toggle() SettingsModel {
	switch m.Focused {
	case 0: // Backend
		switch m.Cfg.Backend {
		case "python": m.Cfg.Backend = "go"
		case "go": m.Cfg.Backend = "both"
		default: m.Cfg.Backend = "python"
		}
	case 1: // Theme
		switch m.Cfg.Theme {
		case "dark": m.Cfg.Theme = "hacker"
		case "hacker": m.Cfg.Theme = "light"
		default: m.Cfg.Theme = "dark"
		}
	}
	return m
}

func (m SettingsModel) View() string {
	var sb strings.Builder
	sb.WriteString(styles.Title.Render("  ⚙  Settings") + "\n\n")

	rows := []struct{ label, val string }{
		{"Backend", m.Cfg.Backend},
		{"Theme", m.Cfg.Theme},
		{"Python Bin", m.Cfg.PythonBin},
		{"Save & Close", "[ Enter ]"},
	}

	for i, row := range rows {
		label := styles.Label.Render("  " + row.label)
		val := styles.Value.Render(row.val)
		line := label + "  " + val
		if i == m.Focused {
			line = styles.Selected.Width(m.Width - 8).Render("  ► " + row.label + "  " + row.val)
		}
		sb.WriteString(line + "\n\n")
	}

	sb.WriteString("\n" + styles.Muted.Render("  ↑↓ navigate   Space/Enter: toggle/select   s: close"))

	return styles.BorderFocused.
		Width(m.Width/2).
		Padding(1, 2).
		Render(sb.String())
}

func boolStr(b bool) string {
	if b { return "ON" }
	return "OFF"
}

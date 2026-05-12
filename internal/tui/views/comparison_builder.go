package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"cryptographer/internal/tui/styles"
)

type ColumnConfig struct {
	AlgoID  string
	Backend string
}

type ComparisonBuilderModel struct {
	Width             int
	Height            int
	Plaintext         string
	Columns           []ColumnConfig
	FocusedIndex      int
	AvailableAlgos    []string
	AvailableBackends []string
}

func NewComparisonBuilder(w, h int) ComparisonBuilderModel {
	return ComparisonBuilderModel{
		Width:             w,
		Height:            h,
		Plaintext:         "Hello World",
		Columns:           []ColumnConfig{{"des", "go"}},
		FocusedIndex:      0,
		AvailableAlgos:    []string{"des", "aes", "substitution", "double_transposition", "rsa", "ecc"},
		AvailableBackends: []string{"go", "python"},
	}
}

func (m ComparisonBuilderModel) NumFields() int {
	return 1 + len(m.Columns)*3 + 2
}

func (m ComparisonBuilderModel) Update(msg tea.KeyMsg) (ComparisonBuilderModel, tea.Cmd) {
	key := msg.String()

	switch key {
	case "up":
		if m.FocusedIndex > 0 {
			m.FocusedIndex--
		}
	case "down", "tab":
		if m.FocusedIndex < m.NumFields()-1 {
			m.FocusedIndex++
		}
	case "shift+tab":
		if m.FocusedIndex > 0 {
			m.FocusedIndex--
		}
	case "left", "right":
		m = m.handleHorizontal(key)
	case "enter":
		m = m.handleEnter()
	case "backspace":
		if m.FocusedIndex == 0 && len(m.Plaintext) > 0 {
			m.Plaintext = m.Plaintext[:len(m.Plaintext)-1]
		}
	default:
		// Normal typing for plaintext
		if m.FocusedIndex == 0 {
			if len(key) == 1 {
				m.Plaintext += key
			} else if key == "space" {
				m.Plaintext += " "
			}
		}
	}
	return m, nil
}

func (m ComparisonBuilderModel) handleHorizontal(dir string) ComparisonBuilderModel {
	idx := m.FocusedIndex
	if idx == 0 {
		return m
	}
	if idx >= 1 && idx < 1+len(m.Columns)*3 {
		colIdx := (idx - 1) / 3
		field := (idx - 1) % 3
		
		if field == 0 { // Algo
			cur := indexOf(m.Columns[colIdx].AlgoID, m.AvailableAlgos)
			if dir == "left" {
				cur = (cur - 1 + len(m.AvailableAlgos)) % len(m.AvailableAlgos)
			} else {
				cur = (cur + 1) % len(m.AvailableAlgos)
			}
			m.Columns[colIdx].AlgoID = m.AvailableAlgos[cur]
		} else if field == 1 { // Backend
			cur := indexOf(m.Columns[colIdx].Backend, m.AvailableBackends)
			if dir == "left" {
				cur = (cur - 1 + len(m.AvailableBackends)) % len(m.AvailableBackends)
			} else {
				cur = (cur + 1) % len(m.AvailableBackends)
			}
			m.Columns[colIdx].Backend = m.AvailableBackends[cur]
		}
	}
	return m
}

func (m ComparisonBuilderModel) handleEnter() ComparisonBuilderModel {
	idx := m.FocusedIndex
	if idx >= 1 && idx < 1+len(m.Columns)*3 {
		colIdx := (idx - 1) / 3
		field := (idx - 1) % 3
		if field == 2 { // Remove
			m.Columns = append(m.Columns[:colIdx], m.Columns[colIdx+1:]...)
			if m.FocusedIndex >= m.NumFields() {
				m.FocusedIndex = m.NumFields() - 1
			}
		}
	} else if idx == 1+len(m.Columns)*3 {
		// Add column
		m.Columns = append(m.Columns, ColumnConfig{"des", "go"})
	}
	return m
}

func indexOf(val string, arr []string) int {
	for i, v := range arr {
		if v == val {
			return i
		}
	}
	return 0
}

func (m ComparisonBuilderModel) View() string {
	var sb strings.Builder
	sb.WriteString(styles.Title.Render("  Comparison Builder") + "\n\n")

	renderRow := func(i int, label, val string) {
		line := styles.Label.Render(fmt.Sprintf("  %-15s", label)) + " " + styles.Value.Render(val)
		if i == m.FocusedIndex {
			line = styles.Selected.Render(fmt.Sprintf("► %-15s", label)) + " " + styles.Value.Render(val)
		}
		sb.WriteString(line + "\n")
	}

	renderRow(0, "Plaintext:", m.Plaintext+"_")
	sb.WriteString("\n")

	for i, col := range m.Columns {
		sb.WriteString(styles.Muted.Render(fmt.Sprintf("  --- Column %d ---", i+1)) + "\n")
		
		idxAlgo := 1 + i*3
		renderRow(idxAlgo, "Algorithm:", fmt.Sprintf("◀ %s ▶", col.AlgoID))
		
		idxBackend := 1 + i*3 + 1
		renderRow(idxBackend, "Backend:", fmt.Sprintf("◀ %s ▶", col.Backend))
		
		idxRemove := 1 + i*3 + 2
		if m.FocusedIndex == idxRemove {
			sb.WriteString(styles.Selected.Render("► [ Remove Column ]") + "\n")
		} else {
			sb.WriteString(styles.Label.Render("  [ Remove Column ]") + "\n")
		}
		sb.WriteString("\n")
	}

	idxAdd := 1 + len(m.Columns)*3
	if m.FocusedIndex == idxAdd {
		sb.WriteString(styles.Selected.Render("► [ + Add Column ]") + "\n\n")
	} else {
		sb.WriteString(styles.Label.Render("  [ + Add Column ]") + "\n\n")
	}

	idxRun := idxAdd + 1
	if m.FocusedIndex == idxRun {
		sb.WriteString(styles.Selected.Render("► [ ▶ RUN COMPARISON ]") + "\n")
	} else {
		sb.WriteString(styles.Label.Render("  [ ▶ RUN COMPARISON ]") + "\n")
	}

	sb.WriteString("\n" + styles.Muted.Render("  ↑↓: navigate   ←→: cycle choices   Enter: execute/remove/add"))

	return lipgloss.Place(m.Width, m.Height, lipgloss.Center, lipgloss.Center,
		styles.BorderNormal.
			Width(m.Width/2 + 10).
			Padding(1, 2).
			Render(sb.String()),
	)
}

func (m ComparisonBuilderModel) IsRunFocused() bool {
	return m.FocusedIndex == m.NumFields()-1
}

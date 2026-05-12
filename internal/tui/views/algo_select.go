package views

import (
	"fmt"
	"strings"

	"cryptographer/internal/tui/styles"

	"github.com/charmbracelet/lipgloss"
)

// AlgorithmEntry describes one selectable algorithm.
type AlgorithmEntry struct {
	ID       string
	Category string
	Name     string
	Ops      []string
	Desc     string
}

// Algorithms is the full catalogue.
var Algorithms = []AlgorithmEntry{
	{ID: "substitution", Category: "Classical", Name: "Substitution Cipher",
		Ops:  []string{"encrypt", "decrypt", "frequency"},
		Desc: "Monoalphabetic substitution with frequency analysis"},
	{ID: "double_transposition", Category: "Classical", Name: "Double Transposition",
		Ops:  []string{"encrypt", "decrypt", "frequency"},
		Desc: "Two-pass columnar transposition cipher"},
	{ID: "des", Category: "Symmetric", Name: "DES",
		Ops:  []string{"encrypt", "decrypt"},
		Desc: "16-round Feistel DES with all standard tables"},
	{ID: "aes", Category: "Symmetric", Name: "AES",
		Ops:  []string{"encrypt", "decrypt"},
		Desc: "AES-128/192/256 with key schedule, CBC mode"},
	{ID: "rsa", Category: "Asymmetric", Name: "RSA",
		Ops:  []string{"generate", "encrypt", "decrypt", "factorize"},
		Desc: "RSA with Miller-Rabin primes & Pollard's rho attack"},
	{ID: "ecc", Category: "Asymmetric", Name: "ECC / ECDH",
		Ops:  []string{"list", "ecdh"},
		Desc: "Elliptic curve over Fp — point arithmetic & Diffie-Hellman"},
	{ID: "comparison", Category: "Tools", Name: "Comparison Builder",
		Ops:  []string{"custom_table"},
		Desc: "Build a custom comparison table across algorithms and backends"},
}

// AlgoSelectModel holds the state for the algorithm selection view.
type AlgoSelectModel struct {
	Selected int
	Width    int
	Height   int
}

func NewAlgoSelect(w, h int) AlgoSelectModel {
	return AlgoSelectModel{Width: w, Height: h}
}

func (m AlgoSelectModel) SelectedAlgo() AlgorithmEntry {
	return Algorithms[m.Selected]
}

func (m AlgoSelectModel) MoveUp() AlgoSelectModel {
	if m.Selected > 0 {
		m.Selected--
	}
	return m
}

func (m AlgoSelectModel) MoveDown() AlgoSelectModel {
	if m.Selected < len(Algorithms)-1 {
		m.Selected++
	}
	return m
}

// View renders the algorithm selector panel.
func (m AlgoSelectModel) View() string {
	var sb strings.Builder

	sb.WriteString(styles.Title.Render("  Algorithms") + "\n\n")

	currentCat := ""
	for i, algo := range Algorithms {
		if algo.Category != currentCat {
			currentCat = algo.Category
			cat := styles.Subtitle.Render("  ── " + currentCat + " ──")
			sb.WriteString(cat + "\n")
		}

		line := fmt.Sprintf("  %s", algo.Name)
		if i == m.Selected {
			sb.WriteString(styles.Selected.Width(m.Width-4).Render(line) + "\n")
		} else {
			sb.WriteString(styles.Unselected.Width(m.Width-4).Render(line) + "\n")
		}
	}

	if m.Selected < len(Algorithms) {
		algo := Algorithms[m.Selected]
		sb.WriteString("\n")
		sb.WriteString(styles.Muted.Render("  "+algo.Desc) + "\n")
		ops := strings.Join(algo.Ops, "  │  ")
		sb.WriteString(styles.Muted.Render("  Ops: ") + styles.Value.Render(ops) + "\n")
	}

	return styles.BorderNormal.
		Width(m.Width - 2).
		Height(m.Height - 2).
		Render(
			lipgloss.NewStyle().
				Width(m.Width - 4).
				Height(m.Height - 4).
				Render(sb.String()),
		)
}

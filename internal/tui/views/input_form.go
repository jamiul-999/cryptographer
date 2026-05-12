package views

import (
	"fmt"
	"strings"

	"cryptographer/internal/tui/styles"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

// Field defines one input field in the form.
type Field struct {
	Label       string
	Placeholder string
	Key         string // maps to AlgoRequest.Params key
	Secret      bool
}

// fieldSets maps algorithm+operation → required fields.
var fieldSets = map[string][]Field{
	"substitution/encrypt": {
		{Label: "Plaintext string", Placeholder: "HELLO WORLD", Key: "plaintext"},
		{Label: "Key (26-letter permutation)", Placeholder: "QWERTYUIOPASDFGHJKLZXCVBNM", Key: "key"},
	},
	"substitution/decrypt": {
		{Label: "Ciphertext", Placeholder: "ITSSG VGKSR", Key: "ciphertext"},
		{Label: "Key (26-letter permutation)", Placeholder: "QWERTYUIOPASDFGHJKLZXCVBNM", Key: "key"},
	},
	"substitution/frequency": {
		{Label: "Ciphertext", Placeholder: "Paste ciphertext here", Key: "ciphertext"},
	},
	"double_transposition/encrypt": {
		{Label: "Plaintext", Placeholder: "ATTACK AT DAWN", Key: "plaintext"},
		{Label: "First permutation key", Placeholder: "CRYPTO", Key: "key1"},
		{Label: "Second permutation key", Placeholder: "SECRET", Key: "key2"},
	},
	"double_transposition/decrypt": {
		{Label: "Ciphertext", Placeholder: "...", Key: "ciphertext"},
		{Label: "First permutation key", Placeholder: "CRYPTO", Key: "key1"},
		{Label: "Second permutation key", Placeholder: "SECRET", Key: "key2"},
		{Label: "Original length (from encrypt output, leave blank for heuristic)", Placeholder: "12", Key: "original_length"},
	},
	"double_transposition/frequency": {
		{Label: "Ciphertext", Placeholder: "Paste ciphertext here", Key: "ciphertext"},
	},
	"des/encrypt": {
		{Label: "Plaintext", Placeholder: "Hello, World!", Key: "plaintext"},
		{Label: "Key (Auto-generated if empty)", Placeholder: "Leave blank to auto-generate", Key: "key"},
	},
	"des/decrypt": {
		{Label: "Ciphertext (hex)", Placeholder: "A1B2C3...", Key: "ciphertext"},
		{Label: "Key", Placeholder: "Paste key from encrypt output", Key: "key"},
	},
	"aes/encrypt": {
		{Label: "Plaintext", Placeholder: "Hello, World!", Key: "plaintext"},
		{Label: "Key (Auto-generated if empty)", Placeholder: "Leave blank to auto-generate", Key: "key"},
	},
	"aes/decrypt": {
		{Label: "Ciphertext", Placeholder: "A1B2C3...", Key: "ciphertext"},
		{Label: "Key", Placeholder: "Paste key from encrypt output", Key: "key"},
		{Label: "IV", Placeholder: "Paste IV from encrypt output", Key: "iv"},
	},
	"rsa/generate": {
		{Label: "Key size (e.g., 512, 1024 bits and randomly generated)", Placeholder: "512", Key: "key_size"},
	},
	"rsa/encrypt": {
		{Label: "Plaintext string", Placeholder: "Secret message", Key: "plaintext"},
		{Label: "Public key (n)", Placeholder: "...", Key: "n"},
		{Label: "Public key (e)", Placeholder: "65537", Key: "e"},
	},
	"rsa/decrypt": {
		{Label: "Ciphertext (as integer or hex)", Placeholder: "...", Key: "ciphertext"},
		{Label: "Public key (n)", Placeholder: "...", Key: "n"},
		{Label: "Private key (d)", Placeholder: "...", Key: "d"},
	},
	"rsa/factorize": {
		{Label: "n (modulus to factor)", Placeholder: "...", Key: "n"},
		{Label: "e (public exponent)", Placeholder: "65537", Key: "e"},
	},
	"ecc/list": {
		{Label: "p (prime field modulus)", Placeholder: "17", Key: "p"},
		{Label: "a (curve coefficient)", Placeholder: "2", Key: "a"},
		{Label: "b (curve coefficient)", Placeholder: "2", Key: "b"},
		{Label: "P(x) — primitive element x", Placeholder: "5", Key: "Gx"},
		{Label: "P(y) — primitive element y", Placeholder: "1", Key: "Gy"},
	},
	"ecc/ecdh": {
		{Label: "p (prime field modulus)", Placeholder: "17", Key: "p"},
		{Label: "a (curve coefficient)", Placeholder: "2", Key: "a"},
		{Label: "b (curve coefficient)", Placeholder: "2", Key: "b"},
		{Label: "P(x) — primitive element x", Placeholder: "5", Key: "Gx"},
		{Label: "P(y) — primitive element y", Placeholder: "1", Key: "Gy"},
		{Label: "n (group order)", Placeholder: "19", Key: "n"},
		{Label: "Alice private key ka (blank = auto-generate)", Placeholder: "3", Key: "ka"},
		{Label: "Bob private key kb (blank = auto-generate)", Placeholder: "7", Key: "kb"},
	},
}

// InputFormModel holds state for a dynamic form.
type InputFormModel struct {
	Fields  []Field
	Inputs  []textinput.Model
	Focused int
	Width   int
	Height  int
	AlgoID  string
	OpID    string
}

// NewInputForm constructs a form for the given algo+op.
func NewInputForm(algoID, opID string, w, h int) InputFormModel {
	key := algoID + "/" + opID
	fields, ok := fieldSets[key]
	if !ok {
		fields = []Field{{Label: "Input", Placeholder: "...", Key: "input"}}
	}

	inputs := make([]textinput.Model, len(fields))
	for i, f := range fields {
		ti := textinput.New()
		ti.Placeholder = f.Placeholder
		ti.CharLimit = 2048
		if f.Secret {
			ti.EchoMode = textinput.EchoPassword
		}
		inputs[i] = ti
	}
	if len(inputs) > 0 {
		inputs[0].Focus()
	}

	return InputFormModel{Fields: fields, Inputs: inputs, Width: w, Height: h, AlgoID: algoID, OpID: opID}
}

// Params extracts the current form values as a params map.
func (m InputFormModel) Params() map[string]string {
	p := make(map[string]string, len(m.Fields))
	for i, f := range m.Fields {
		p[f.Key] = m.Inputs[i].Value()
	}
	return p
}

// FocusNext moves to the next input field.
func (m InputFormModel) FocusNext() InputFormModel {
	m.Inputs[m.Focused].Blur()
	m.Focused = (m.Focused + 1) % len(m.Inputs)
	m.Inputs[m.Focused].Focus()
	return m
}

// FocusPrev moves to the previous input field.
func (m InputFormModel) FocusPrev() InputFormModel {
	m.Inputs[m.Focused].Blur()
	m.Focused = (m.Focused - 1 + len(m.Inputs)) % len(m.Inputs)
	m.Inputs[m.Focused].Focus()
	return m
}

// Update passes a key message to the focused input.
func (m InputFormModel) UpdateFocused(msg interface{}) (InputFormModel, interface{}) {
	var cmd interface{}
	m.Inputs[m.Focused], _ = m.Inputs[m.Focused].Update(msg)
	return m, cmd
}

// View renders the form.
func (m InputFormModel) View() string {
	var sb strings.Builder

	title := fmt.Sprintf("  %s  ›  %s", strings.ToUpper(m.AlgoID), strings.ToUpper(m.OpID))
	sb.WriteString(styles.Title.Render(title) + "\n\n")

	for i, f := range m.Fields {
		label := styles.Label.Render("  " + f.Label)
		sb.WriteString(label + "\n")
		inputStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Width(m.Width-8).
			Padding(0, 1)
		if i == m.Focused {
			inputStyle = inputStyle.BorderForeground(styles.ColorAccent)
		} else {
			inputStyle = inputStyle.BorderForeground(styles.ColorMuted)
		}
		sb.WriteString(inputStyle.Render(m.Inputs[i].View()) + "\n\n")
	}

	hint := styles.Muted.Render("  Tab/Shift+Tab: next/prev field   Enter: run   Esc: back")
	sb.WriteString(hint)

	return styles.BorderNormal.
		Width(m.Width - 2).
		Height(m.Height - 2).
		Render(sb.String())
}

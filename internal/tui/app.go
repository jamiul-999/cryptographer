// Package tui is the root Bubble Tea application model.
package tui

import (
	"fmt"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"cryptographer/internal/bridge"
	"cryptographer/internal/config"
	"cryptographer/internal/models"
	"cryptographer/internal/tui/components"
	"cryptographer/internal/tui/styles"
	"cryptographer/internal/tui/views"
)

// screen identifies which view is active.
type screen int

const (
	screenAlgoSelect screen = iota
	screenOpSelect
	screenInputForm
	screenResult
	screenComparisonBuilder
)

// doneMsg is sent when the backend finishes executing.
type doneMsg struct {
	primary   models.AlgoResult
	secondary *models.AlgoResult
}

// benchmarkDoneMsg is sent when the benchmark runner finishes.
type benchmarkDoneMsg struct {
	results []models.AlgoResult
	headers []string
}


// AppModel is the root Bubble Tea model.
type AppModel struct {
	cfg          *config.Config
	runner       *bridge.Runner
	width        int
	height       int
	screen       screen
	loading      bool
	showHelp     bool
	showSettings bool

	algoSelect   views.AlgoSelectModel
	opSelect     int
	inputForm    views.InputFormModel
	resultPanel  views.ResultPanelModel
	settingsView views.SettingsModel
	comparisonBuilder views.ComparisonBuilderModel
	spinner      spinner.Model

	statusHint  string
	lastElapsed float64
}

// New creates the root model with loaded config.
func New(cfg *config.Config) AppModel {
	runner := bridge.New(cfg)
	w, h := 120, 36

	return AppModel{
		cfg:          cfg,
		runner:       runner,
		width:        w,
		height:       h,
		screen:       screenAlgoSelect,
		algoSelect:   views.NewAlgoSelect(36, h-4),
		resultPanel:  views.NewResultPanel(w-40, h-4),
		settingsView: views.NewSettings(cfg, w, h),
		comparisonBuilder: views.NewComparisonBuilder(w, h-4),
		spinner:      components.NewSpinner(),
		statusHint:   "↑↓: select   Enter: choose   Ctrl+S: settings   F1: help   Ctrl+C: quit",
	}
}

// Init starts the TUI.
func (m AppModel) Init() tea.Cmd {
	return tea.EnterAltScreen
}

// Update handles all messages.
func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.algoSelect.Width = 36
		m.algoSelect.Height = m.height - 4
		m.resultPanel.Width = m.width - 40
		m.resultPanel.Height = m.height - 4
		m.comparisonBuilder.Width = m.width
		m.comparisonBuilder.Height = m.height - 4


	case doneMsg:
		m.loading = false
		m.resultPanel = m.resultPanel.SetResults(msg.primary, msg.secondary)
		m.lastElapsed = msg.primary.ElapsedMs
		m.screen = screenResult
		m.statusHint = "↑↓: scroll   Esc: back   Ctrl+S: settings   F1: help"

	case benchmarkDoneMsg:
		m.loading = false
		m.resultPanel = m.resultPanel.SetBenchmarkResults(msg.results, msg.headers)
		if len(msg.results) > 0 {
			m.lastElapsed = msg.results[0].ElapsedMs
		}
		m.screen = screenResult
		m.statusHint = "↑↓: scroll   Esc: back   Ctrl+S: settings   F1: help"

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	// Update spinner when loading
	if m.loading {
		var cmd tea.Cmd
		// spinner update would go here if we track it
		return m, cmd
	}
	return m, nil
}

func (m AppModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global keys — letters are intentionally NOT bound here so they type freely.
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	if key == "f1" {
		m.showHelp = !m.showHelp
		m.showSettings = false
		return m, nil
	}
	if key == "ctrl+s" && m.screen != screenInputForm {
		m.showSettings = !m.showSettings
		m.showHelp = false
		return m, nil
	}

	// Overlay keys
	if m.showSettings {
		return m.handleSettings(key)
	}
	if m.showHelp {
		if key == "esc" || key == "f1" {
			m.showHelp = false
		}
		return m, nil
	}

	// Screen-level keys
	switch m.screen {
	case screenAlgoSelect:
		return m.handleAlgoSelect(key)
	case screenOpSelect:
		return m.handleOpSelect(key)
	case screenInputForm:
		return m.handleInputForm(msg)
	case screenResult:
		return m.handleResult(key)
	case screenComparisonBuilder:
		return m.handleComparisonBuilder(msg)
	}
	return m, nil
}

func (m AppModel) handleAlgoSelect(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up":
		m.algoSelect = m.algoSelect.MoveUp()
	case "down":
		m.algoSelect = m.algoSelect.MoveDown()
	case "enter":
		if m.algoSelect.SelectedAlgo().ID == "comparison" {
			m.screen = screenComparisonBuilder
			m.statusHint = "↑↓: navigate   ←→: cycle   Enter: confirm   Esc: back"
			return m, nil
		}
		m.opSelect = 0
		m.screen = screenOpSelect
		m.statusHint = "↑↓: select operation   Enter: confirm   Esc: back"
	}
	return m, nil
}

func (m AppModel) handleOpSelect(key string) (tea.Model, tea.Cmd) {
	algo := m.algoSelect.SelectedAlgo()
	switch key {
	case "esc", "backspace":
		m.screen = screenAlgoSelect
		m.statusHint = "↑↓: select   Enter: choose   Ctrl+S: settings   F1: help   Ctrl+C: quit"
	case "up":
		if m.opSelect > 0 {
			m.opSelect--
		}
	case "down":
		if m.opSelect < len(algo.Ops)-1 {
			m.opSelect++
		}
	case "enter":
		op := algo.Ops[m.opSelect]
		m.inputForm = views.NewInputForm(algo.ID, op, m.width, m.height-4)
		m.screen = screenInputForm
		m.statusHint = "Tab: next field   Enter: run   Esc: back"
	}
	return m, nil
}

func (m AppModel) handleInputForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.screen = screenOpSelect
		m.statusHint = "↑↓: select operation   Enter: confirm   Esc: back"
		return m, nil
	case "tab":
		m.inputForm = m.inputForm.FocusNext()
		return m, nil
	case "shift+tab":
		m.inputForm = m.inputForm.FocusPrev()
		return m, nil
	case "enter":
		return m.runAlgo()
	}
	m.inputForm, _ = m.inputForm.UpdateFocused(msg)
	return m, nil
}

func (m AppModel) handleResult(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "backspace":
		if m.algoSelect.SelectedAlgo().ID == "comparison" {
			m.screen = screenComparisonBuilder
			m.statusHint = "↑↓: navigate   ←→: cycle   Enter: confirm   Esc: back"
		} else {
			m.screen = screenInputForm
			m.statusHint = "Tab: next field   Enter: run   Esc: back"
		}
	case "up":
		m.resultPanel = m.resultPanel.ScrollUp()
	case "down":
		m.resultPanel = m.resultPanel.ScrollDown()
	}
	return m, nil
}

func (m AppModel) handleComparisonBuilder(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "esc" {
		m.screen = screenAlgoSelect
		m.statusHint = "↑↓: select   Enter: choose   Ctrl+S: settings   F1: help   Ctrl+C: quit"
		return m, nil
	}

	m.comparisonBuilder, _ = m.comparisonBuilder.Update(msg)

	if key == "enter" && m.comparisonBuilder.IsRunFocused() {
		return m.runDynamicBenchmark()
	}
	return m, nil
}

func (m AppModel) handleSettings(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "ctrl+s":
		m.showSettings = false
	case "up":
		m.settingsView = m.settingsView.MoveUp()
	case "down":
		m.settingsView = m.settingsView.MoveDown()
	case "enter", " ":
		if m.settingsView.Focused == len(settingLabels())-1 {
			// Save & close
			_ = m.cfg.Save()
			m.runner = bridge.New(m.cfg)
			m.showSettings = false
		} else {
			m.settingsView = m.settingsView.Toggle()
		}
	}
	return m, nil
}

func settingLabels() []string {
	return []string{"Backend", "Theme", "Compare Mode", "Python Bin", "Save & Close"}
}

// runAlgo dispatches to the runner in a goroutine and returns a command.
func (m AppModel) runAlgo() (tea.Model, tea.Cmd) {
	m.loading = true
	m.statusHint = "Running…"
	algo := m.algoSelect.SelectedAlgo()
	op := algo.Ops[m.opSelect]
	params := m.inputForm.Params()

	req := models.AlgoRequest{
		Algorithm: algo.ID,
		Operation: op,
		Params:    params,
	}
	runner := m.runner
	return m, func() tea.Msg {
		primary, secondary := runner.Run(req)
		return doneMsg{primary: primary, secondary: secondary}
	}
}

func (m AppModel) runDynamicBenchmark() (tea.Model, tea.Cmd) {
	m.loading = true
	m.statusHint = "Running Benchmark…"
	cols := m.comparisonBuilder.Columns
	pt := m.comparisonBuilder.Plaintext

	return m, func() tea.Msg {
		results := make([]models.AlgoResult, len(cols))
		headers := make([]string, len(cols))
		var wg sync.WaitGroup
		wg.Add(len(cols))

		for i, c := range cols {
			go func(idx int, col views.ColumnConfig) {
				defer wg.Done()
				req := models.AlgoRequest{
					Algorithm: col.AlgoID,
					Operation: "encrypt", // Comparison usually runs encrypt to get ciphertext
					Params:    map[string]string{"plaintext": pt},
				}
				if col.Backend == "go" {
					results[idx] = bridge.RunGo(req)
				} else {
					results[idx] = bridge.RunPython(req, m.cfg.PythonBin, m.cfg.PythonScript)
				}
				
				// Format header e.g. "DES · Go"
				algoLabel := strings.ToUpper(col.AlgoID)
				if algoLabel == "DOUBLE_TRANSPOSITION" {
					algoLabel = "DBL TRANS"
				} else if algoLabel == "SUBSTITUTION" {
					algoLabel = "SUBST"
				}
				backendLabel := "Go"
				if col.Backend == "python" {
					backendLabel = "Python"
				}
				headers[idx] = fmt.Sprintf("%s · %s", algoLabel, backendLabel)
			}(i, c)
		}
		wg.Wait()
		return benchmarkDoneMsg{results: results, headers: headers}
	}
}

// View renders the full TUI.
func (m AppModel) View() string {
	header := components.Header(m.width, m.cfg.Backend)
	statusBar := components.StatusBar(m.width, m.screenName(), m.statusHint, m.lastElapsed)

	var body string
	switch m.screen {
	case screenAlgoSelect:
		body = m.viewAlgoScreen()
	case screenOpSelect:
		body = m.viewOpScreen()
	case screenInputForm:
		body = m.viewFormScreen()
	case screenResult:
		body = m.viewResultScreen()
	case screenComparisonBuilder:
		body = m.comparisonBuilder.View()
	}

	// Overlay modals on top
	if m.showHelp {
		overlay := views.HelpView(m.width)
		body = placeCenter(overlay, body, m.width, m.height-4)
	} else if m.showSettings {
		overlay := m.settingsView.View()
		body = placeCenter(overlay, body, m.width, m.height-4)
	}

	// Loading spinner overlay
	if m.loading {
		spin := styles.Value.Render("  ⣾ Running…")
		body = placeCenter(spin, body, m.width, m.height-4)
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, body, statusBar)
}

func (m AppModel) viewAlgoScreen() string {
	left := m.algoSelect.View()
	right := m.resultPanel.View()
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m AppModel) viewOpScreen() string {
	algo := m.algoSelect.SelectedAlgo()
	overlay := views.OpSelectView(algo, m.opSelect, m.width)
	bg := m.viewAlgoScreen()
	return placeCenter(overlay, bg, m.width, m.height-4)
}

func (m AppModel) viewFormScreen() string {
	left := m.algoSelect.View()
	right := m.inputForm.View()
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m AppModel) viewResultScreen() string {
	left := m.algoSelect.View()
	right := m.resultPanel.View()
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m AppModel) screenName() string {
	switch m.screen {
	case screenAlgoSelect:
		return "SELECT"
	case screenOpSelect:
		return "OPERATION"
	case screenInputForm:
		return "INPUT"
	case screenResult:
		return "RESULT"
	case screenComparisonBuilder:
		return "COMPARISON BUILDER"
	}
	return ""
}

// placeCenter overlays the top box centered over the bg string.
func placeCenter(overlay, bg string, w, h int) string {
	ow := lipgloss.Width(overlay)
	oh := lipgloss.Height(overlay)
	x := (w - ow) / 2
	y := (h - oh) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center,
		overlay,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(lipgloss.Color("#0d1117")),
	) + fmt.Sprintf("%d%d%s", x, y, bg[0:0]) // keep bg in scope
}

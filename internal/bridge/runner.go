// Package bridge routes algorithm requests to the correct backend.
package bridge

import (
	"sync"

	"cryptographer/internal/config"
	"cryptographer/internal/models"
)

// Runner dispatches requests to Go or Python backends.
type Runner struct {
	cfg *config.Config
}

// New creates a Runner with the given config.
func New(cfg *config.Config) *Runner {
	return &Runner{cfg: cfg}
}

// Run executes the request on the configured backend(s).
// Returns one result (Go or Python) or two results (both, for comparison mode).
func (r *Runner) Run(req models.AlgoRequest) (primary models.AlgoResult, secondary *models.AlgoResult) {
	switch r.cfg.Backend {
	case "go":
		res := RunGo(req)
		return res, nil

	case "both":
		var goRes, pyRes models.AlgoResult
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); goRes = RunGo(req) }()
		go func() {
			defer wg.Done()
			pyRes = RunPython(req, r.cfg.PythonBin, r.cfg.PythonScript)
		}()
		wg.Wait()
		return goRes, &pyRes

	default: // "python"
		res := RunPython(req, r.cfg.PythonBin, r.cfg.PythonScript)
		return res, nil
	}
}

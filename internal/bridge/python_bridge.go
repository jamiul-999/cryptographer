// Package bridge provides the Python subprocess bridge.
package bridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"cryptographer/internal/models"
)

// pythonResponse mirrors the JSON structure returned by py/main.py
type pythonResponse struct {
	Output    map[string]string `json:"output"`
	ElapsedMs float64           `json:"elapsed_ms"`
	Error     string            `json:"error"`
}

// RunPython dispatches req to the Python backend via subprocess.
// pythonBin is the interpreter (e.g. "python3").
// scriptPath is the absolute or relative path to py/main.py.
func RunPython(req models.AlgoRequest, pythonBin, scriptPath string) models.AlgoResult {
	start := time.Now()

	payload, err := json.Marshal(req)
	if err != nil {
		return models.AlgoResult{Algorithm: req.Algorithm, Operation: req.Operation, Error: fmt.Sprintf("marshal error: %v", err), Backend: "python"}
	}

	// Resolve script path relative to working directory if needed
	absScript, err := filepath.Abs(scriptPath)
	if err != nil {
		absScript = scriptPath
	}

	cmd := exec.Command(pythonBin, absScript)
	cmd.Stdin = bytes.NewReader(payload)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		elapsed := float64(time.Since(start).Milliseconds())
		return models.AlgoResult{
			Error:     fmt.Sprintf("python error: %v\nstderr: %s", err, stderr.String()),
			Backend:   "python",
			ElapsedMs: elapsed,
		}
	}

	var resp pythonResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return models.AlgoResult{
			Error:   fmt.Sprintf("decode error: %v\nraw: %s", err, stdout.String()),
			Backend: "python",
		}
	}

	return models.AlgoResult{
		Algorithm: req.Algorithm,
		Operation: req.Operation,
		Output:    resp.Output,
		ElapsedMs: resp.ElapsedMs,
		Error:     resp.Error,
		Backend:   "python",
	}
}

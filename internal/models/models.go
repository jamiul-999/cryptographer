package models

// AlgoRequest is the input sent to any backend.
type AlgoRequest struct {
	Algorithm string            `json:"algorithm"`
	Operation string            `json:"operation"`
	Params    map[string]string `json:"params"`
}

// AlgoResult is the output returned by any backend.
type AlgoResult struct {
	Algorithm string            `json:"algorithm"`
	Operation string            `json:"operation"`
	Output    map[string]string `json:"output"`
	Backend   string            `json:"backend"`
	ElapsedMs float64           `json:"elapsed_ms"`
	Error     string            `json:"error"`
}

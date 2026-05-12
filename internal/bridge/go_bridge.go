package bridge

import (
	"cryptographer/internal/engine"
	"cryptographer/internal/models"
)

// RunGo dispatches to the native Go engine.
func RunGo(req models.AlgoRequest) models.AlgoResult {
	res := engine.RunGo(req)
	res.Algorithm = req.Algorithm
	res.Operation = req.Operation
	return res
}

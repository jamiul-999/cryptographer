// Package engine provides Go-native crypto implementations and a dispatch table.
package engine

import (
	"fmt"
	"time"

	"cryptographer/internal/engine/asymmetric"
	"cryptographer/internal/engine/classical"
	"cryptographer/internal/engine/symmetric"
	"cryptographer/internal/models"
)

// RunGo dispatches an AlgoRequest to the correct Go engine function.
func RunGo(req models.AlgoRequest) models.AlgoResult {
	start := time.Now()
	var (
		out map[string]string
		err error
	)

	switch req.Algorithm {
	case "substitution":
		out, err = classical.Substitution(req.Operation, req.Params)
	case "double_transposition":
		out, err = classical.DoubleTransposition(req.Operation, req.Params)
	case "des":
		out, err = symmetric.DES(req.Operation, req.Params)
	case "aes":
		out, err = symmetric.AES(req.Operation, req.Params)
	case "rsa":
		out, err = asymmetric.RSA(req.Operation, req.Params)
	case "ecc":
		out, err = asymmetric.ECC(req.Operation, req.Params)
	default:
		err = fmt.Errorf("unknown algorithm: %q", req.Algorithm)
	}

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	result := models.AlgoResult{Backend: "go", ElapsedMs: elapsed}
	if err != nil {
		result.Error = err.Error()
	} else {
		result.Output = out
	}
	return result
}

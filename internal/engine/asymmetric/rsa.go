// Package asymmetric implements RSA and ECC from scratch in Go.
package asymmetric

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// ─────────────────────────────────────────────
// RSA helpers
// ─────────────────────────────────────────────

var bigOne = big.NewInt(1)
var bigTwo = big.NewInt(2)

func generatePrime(bits int) (*big.Int, error) {
	return rand.Prime(rand.Reader, bits)
}

func textToInt(text string) *big.Int {
	return new(big.Int).SetBytes([]byte(text))
}

func intToText(n *big.Int) string {
	return string(n.Bytes())
}

// pollardRho attempts to find a non-trivial factor of n.
func pollardRho(n *big.Int) *big.Int {
	if new(big.Int).Mod(n, bigTwo).Sign() == 0 {
		return bigTwo
	}
	x, _ := rand.Int(rand.Reader, new(big.Int).Sub(n, bigTwo))
	x.Add(x, bigTwo)
	y := new(big.Int).Set(x)
	c, _ := rand.Int(rand.Reader, new(big.Int).Sub(n, bigOne))
	c.Add(c, bigOne)
	d := new(big.Int).Set(bigOne)

	f := func(v *big.Int) *big.Int {
		r := new(big.Int)
		r.Mul(v, v)
		r.Add(r, c)
		r.Mod(r, n)
		return r
	}

	maxIter := 100_000
	for d.Cmp(bigOne) == 0 && maxIter > 0 {
		maxIter--
		x = f(x)
		y = f(f(y))
		diff := new(big.Int).Sub(x, y)
		diff.Abs(diff)
		d.GCD(nil, nil, diff, n)
	}
	if maxIter == 0 || d.Cmp(n) == 0 {
		return nil
	}
	return d
}

// RSA is the public entry point for the RSA algorithm.
func RSA(operation string, params map[string]string) (map[string]string, error) {
	op := strings.ToLower(operation)

	switch op {
	case "generate":
		bits := 512
		switch params["key_size"] {
		case "256":
			bits = 256
		case "1024":
			bits = 1024
		case "2048":
			bits = 2048
		}
		half := bits / 2

		p, err := generatePrime(half)
		if err != nil {
			return nil, err
		}
		q, err := generatePrime(half)
		if err != nil {
			return nil, err
		}
		for q.Cmp(p) == 0 {
			q, err = generatePrime(half)
			if err != nil {
				return nil, err
			}
		}

		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(
			new(big.Int).Sub(p, bigOne),
			new(big.Int).Sub(q, bigOne),
		)
		e := big.NewInt(65537)
		d := new(big.Int).ModInverse(e, phi)

		return map[string]string{
			"public_key_n":  n.String(),
			"public_key_e":  e.String(),
			"private_key_d": d.String(),
			"prime_p":       p.String(),
			"prime_q":       q.String(),
			"phi_n":         phi.String(),
			"key_size":      fmt.Sprintf("%d bits", bits),
		}, nil

	case "encrypt":
		n, ok1 := new(big.Int).SetString(params["n"], 10)
		e, ok2 := new(big.Int).SetString(params["e"], 10)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid n or e")
		}
		m := textToInt(params["plaintext"])
		if m.Cmp(n) >= 0 {
			return nil, fmt.Errorf("message too large for key size")
		}
		c := new(big.Int).Exp(m, e, n)
		return map[string]string{
			"ciphertext_int": c.String(),
			"ciphertext_hex": fmt.Sprintf("0x%x", c),
		}, nil

	case "decrypt":
		c, ok1 := new(big.Int).SetString(params["ciphertext"], 10)
		n, ok2 := new(big.Int).SetString(params["n"], 10)
		d, ok3 := new(big.Int).SetString(params["d"], 10)
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("invalid ciphertext, n, or d")
		}
		m := new(big.Int).Exp(c, d, n)
		return map[string]string{"plaintext": intToText(m)}, nil

	case "factorize":
		n, ok := new(big.Int).SetString(params["n"], 10)
		if !ok {
			return nil, fmt.Errorf("invalid n")
		}
		if n.ProbablyPrime(20) {
			return map[string]string{"result": fmt.Sprintf("%s is prime — cannot factor.", n)}, nil
		}
		var p *big.Int
		for i := 0; i < 20 && p == nil; i++ {
			p = pollardRho(n)
		}
		if p == nil {
			return map[string]string{"result": "Factorization failed (n too large or took too long)."}, nil
		}
		q := new(big.Int).Div(n, p)
		check := new(big.Int).Mul(p, q)
		if check.Cmp(n) != 0 {
			return map[string]string{"result": "Factorization returned invalid factors."}, nil
		}
		phi := new(big.Int).Mul(
			new(big.Int).Sub(p, bigOne),
			new(big.Int).Sub(q, bigOne),
		)
		e := big.NewInt(65537)
		d := new(big.Int).ModInverse(e, phi)
		dStr := "could not compute"
		if d != nil {
			dStr = d.String()
		}

		return map[string]string{
			"factor_p":          p.String(),
			"factor_q":          q.String(),
			"recovered_phi":     phi.String(),
			"recovered_private": dStr,
		}, nil

	default:
		return nil, fmt.Errorf("unknown operation %q for RSA", operation)
	}
}

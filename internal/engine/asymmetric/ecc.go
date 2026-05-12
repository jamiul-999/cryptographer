package asymmetric

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

var inf = [2]*big.Int{nil, nil}

func isInf(p [2]*big.Int) bool { return p[0] == nil }

// modInvECC returns the modular inverse of a mod m.
// Returns (0, error) if the inverse does not exist, preventing a nil-dereference panic.
func modInvECC(a, m *big.Int) (*big.Int, error) {
	inv := new(big.Int).ModInverse(new(big.Int).Mod(a, m), m)
	if inv == nil {
		return new(big.Int), fmt.Errorf("modular inverse does not exist (gcd ≠ 1): points may lie on a singular or malformed curve")
	}
	return inv, nil
}

func pointAdd(P, Q [2]*big.Int, a, p *big.Int) ([2]*big.Int, error) {
	if isInf(P) {
		return Q, nil
	}
	if isInf(Q) {
		return P, nil
	}
	px, py := P[0], P[1]
	qx, qy := Q[0], Q[1]
	var lam *big.Int
	if px.Cmp(qx) == 0 {
		if py.Cmp(qy) != 0 {
			return inf, nil
		}
		if py.Sign() == 0 {
			return inf, nil
		}
		// lam = (3x²+a) / 2y
		num := new(big.Int).Mul(px, px)
		num.Mul(num, big.NewInt(3))
		num.Add(num, a)
		den := new(big.Int).Mul(bigTwo, py)
		inv, err := modInvECC(den, p)
		if err != nil {
			return inf, err
		}
		lam = new(big.Int).Mul(num, inv)
	} else {
		num := new(big.Int).Sub(qy, py)
		den := new(big.Int).Sub(qx, px)
		inv, err := modInvECC(den, p)
		if err != nil {
			return inf, err
		}
		lam = new(big.Int).Mul(num, inv)
	}
	lam.Mod(lam, p)
	rx := new(big.Int).Mul(lam, lam)
	rx.Sub(rx, px)
	rx.Sub(rx, qx)
	rx.Mod(rx, p)
	ry := new(big.Int).Sub(px, rx)
	ry.Mul(lam, ry)
	ry.Sub(ry, py)
	ry.Mod(ry, p)
	return [2]*big.Int{rx, ry}, nil
}

func pointMul(k *big.Int, P [2]*big.Int, a, p *big.Int) ([2]*big.Int, error) {
	result := inf
	addend := P
	k = new(big.Int).Set(k)
	for k.Sign() > 0 {
		if k.Bit(0) == 1 {
			var err error
			result, err = pointAdd(result, addend, a, p)
			if err != nil {
				return inf, err
			}
		}
		var err error
		addend, err = pointAdd(addend, addend, a, p)
		if err != nil {
			return inf, err
		}
		k.Rsh(k, 1)
	}
	return result, nil
}

// isOnCurve checks that P satisfies y² ≡ x³ + ax + b (mod p).
func isOnCurve(P [2]*big.Int, a, b, p *big.Int) bool {
	if isInf(P) {
		return true
	}
	lhs := new(big.Int).Mul(P[1], P[1])
	lhs.Mod(lhs, p)

	rhs := new(big.Int).Mul(P[0], P[0])
	rhs.Mul(rhs, P[0])
	rhs.Add(rhs, new(big.Int).Mul(a, P[0]))
	rhs.Add(rhs, b)
	rhs.Mod(rhs, p)

	return lhs.Cmp(rhs) == 0
}

// isNonSingular checks 4a³ + 27b² ≢ 0 (mod p).
// A zero discriminant means the curve is singular (cusp or self-intersection)
// and the group law breaks down.
func isNonSingular(a, b, p *big.Int) bool {
	a3 := new(big.Int).Mul(a, a)
	a3.Mul(a3, a)
	a3.Mul(a3, big.NewInt(4))

	b2 := new(big.Int).Mul(b, b)
	b2.Mul(b2, big.NewInt(27))

	disc := new(big.Int).Add(a3, b2)
	disc.Mod(disc, p)
	return disc.Sign() != 0
}

// p256 domain parameters (NIST P-256 / secp256r1)
var (
	p256p, _  = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	p256a, _  = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
	p256b, _  = new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
	p256Gx, _ = new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	p256Gy, _ = new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
	p256n, _  = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
)

func getParams(params map[string]string) (p, a, b *big.Int, G [2]*big.Int, n *big.Int, err error) {
	// Use custom params if 'p' is explicitly provided (works with or without use_default flag).
	if params["p"] != "" || params["use_default"] == "false" {
		parseInt := func(key string) (*big.Int, error) {
			v, ok := new(big.Int).SetString(params[key], 10)
			if !ok {
				return nil, fmt.Errorf("invalid curve parameter %q (value: %q)", key, params[key])
			}
			return v, nil
		}
		if p, err = parseInt("p"); err != nil {
			return
		}
		if a, err = parseInt("a"); err != nil {
			return
		}
		if b, err = parseInt("b"); err != nil {
			return
		}
		var gx, gy *big.Int
		if gx, err = parseInt("Gx"); err != nil {
			return
		}
		if gy, err = parseInt("Gy"); err != nil {
			return
		}
		// n is optional — list derives it by enumeration; ecdh requires it
		if params["n"] != "" {
			if n, err = parseInt("n"); err != nil {
				return
			}
		}
		G = [2]*big.Int{gx, gy}
		return
	}
	return p256p, p256a, p256b, [2]*big.Int{p256Gx, p256Gy}, p256n, nil
}

// ECC is the public entry point for ECC operations.
func ECC(operation string, params map[string]string) (map[string]string, error) {
	op := strings.ToLower(operation)
	p, a, b, G, n, err := getParams(params)
	if err != nil {
		return nil, err
	}

	switch op {
	case "list":
		// Validate custom curve
		if params["use_default"] == "false" && !isNonSingular(a, b, p) {
			return nil, fmt.Errorf("custom curve is singular (4a³ + 27b² ≡ 0 mod p): group law is undefined")
		}

		// If n was provided and is too large, reject early. Otherwise enumerate up to 10000.
		if n != nil && n.Cmp(big.NewInt(10000)) > 0 {
			return map[string]string{"error": "p too large for enumeration"}, nil
		}

		var lines []string
		current := G
		k := big.NewInt(1)
		for {
			lines = append(lines, fmt.Sprintf("%sP = (%s, %s)", k.String(), current[0].String(), current[1].String()))
			next, err := pointAdd(current, G, a, p)
			if err != nil {
				return nil, err
			}
			k = new(big.Int).Add(k, bigOne)
			if isInf(next) {
				lines = append(lines, fmt.Sprintf("%sP = ∞", k.String()))
				break
			}
			current = next
		}
		order := k // order derived from enumeration

		// Generate a random private key in [1, order) and compute the public key
		privKey, err := randBigInt(order)
		if err != nil {
			return nil, err
		}
		pubKey, err := pointMul(privKey, G, a, p)
		if err != nil {
			return nil, err
		}

		// return map[string]string{
		// 	"curve":        fmt.Sprintf("y² = x³ + %sx + %s (mod %s)", a, b, p),
		// 	"multiples":    strings.Join(lines, "\n"),
		// 	"order":        order.String(),
		// 	"private_key":  privKey.String(),
		// 	"public_key_x": pubKey[0].String(),
		// 	"public_key_y": pubKey[1].String(),
		// }, nil
		return map[string]string{
			"number_of_ps": order.String(),
			"all_ps":       strings.Join(lines, "\n"),
			"private_key":  privKey.String(),
			"public_key":   fmt.Sprintf("(%s, %s)", pubKey[0], pubKey[1]),
		}, nil

	case "ecdh":
		// Validate custom curve
		if params["use_default"] == "false" && !isNonSingular(a, b, p) {
			return nil, fmt.Errorf("custom curve is singular (4a³ + 27b² ≡ 0 mod p): group law is undefined")
		}
		if n == nil {
			return nil, fmt.Errorf("ecdh requires group order n")
		}
		ka, err := paramOrRand(params["ka"], n)
		if err != nil {
			return nil, fmt.Errorf("invalid Alice private key (ka): %w", err)
		}
		kb, err := paramOrRand(params["kb"], n)
		if err != nil {
			return nil, fmt.Errorf("invalid Bob private key (kb): %w", err)
		}
		_, err = pointMul(ka, G, a, p)
		if err != nil {
			return nil, fmt.Errorf("Alice key generation failed: %w", err)
		}
		Qb, err := pointMul(kb, G, a, p)
		if err != nil {
			return nil, fmt.Errorf("Bob key generation failed: %w", err)
		}
		shared, err := pointMul(ka, Qb, a, p)
		if err != nil {
			return nil, fmt.Errorf("shared secret computation failed: %w", err)
		}
		// return map[string]string{
		// 	"alice_private": ka.String(),
		// 	"alice_public":  fmt.Sprintf("(%s, %s)", Qa[0], Qa[1]),
		// 	"bob_private":   kb.String(),
		// 	"bob_public":    fmt.Sprintf("(%s, %s)", Qb[0], Qb[1]),
		// 	"shared_key":    shared[0].String(),
		// }, nil
		return map[string]string{
			"shared_key": fmt.Sprintf("(%s, %s)", shared[0], shared[1]),
		}, nil

	default:
		return nil, fmt.Errorf("unknown operation %q for ECC", operation)
	}
}

// randBigInt returns a cryptographically random integer in [1, max).
func randBigInt(max *big.Int) (*big.Int, error) {
	if max.Cmp(bigOne) <= 0 {
		return nil, fmt.Errorf("randBigInt: max must be > 1")
	}
	range_ := new(big.Int).Sub(max, bigOne) // range = max - 1
	r, err := rand.Int(rand.Reader, range_) // r in [0, max-2]
	if err != nil {
		return nil, err
	}
	return r.Add(r, bigOne), nil // shift to [1, max-1]
}

// paramOrRand parses s as a base-10 big.Int private key.
// Returns an error if s is non-empty but not a valid integer (so the caller
// knows the user's key was ignored rather than silently replaced).
func paramOrRand(s string, max *big.Int) (*big.Int, error) {
	if s != "" && s != "0" {
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("not a valid integer: %q", s)
		}
		return v, nil
	}
	r, err := randBigInt(max)
	return r, err
}

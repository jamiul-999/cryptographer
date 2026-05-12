package symmetric

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// ─────────────────────────────────────────────
// AES S-Box and Inverse
// ─────────────────────────────────────────────

var sbox = [256]byte{
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
}

var invSbox [256]byte
var rcon = [10]byte{0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36}

func init() {
	for i, v := range sbox {
		invSbox[v] = byte(i)
	}
}

// ─────────────────────────────────────────────
// GF(2^8) arithmetic
// ─────────────────────────────────────────────

func xtime(a byte) byte {
	if a&0x80 != 0 {
		return (a<<1) ^ 0x1b
	}
	return a << 1
}

func gmul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		a = xtime(a)
		b >>= 1
	}
	return p
}

// ─────────────────────────────────────────────
// AES State operations
// ─────────────────────────────────────────────

type state [4][4]byte

func bytesToState(block []byte) state {
	var s state
	for i := 0; i < 16; i++ {
		s[i%4][i/4] = block[i]
	}
	return s
}

func stateToBytes(s state) []byte {
	out := make([]byte, 16)
	for c := 0; c < 4; c++ {
		for r := 0; r < 4; r++ {
			out[c*4+r] = s[r][c]
		}
	}
	return out
}

func subBytes(s state) state {
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			s[r][c] = sbox[s[r][c]]
		}
	}
	return s
}

func invSubBytes(s state) state {
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			s[r][c] = invSbox[s[r][c]]
		}
	}
	return s
}

func shiftRows(s state) state {
	s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
	s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
	s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]
	return s
}

func invShiftRows(s state) state {
	s[1][0], s[1][1], s[1][2], s[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
	s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
	s[3][0], s[3][1], s[3][2], s[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]
	return s
}

func mixColumns(s state) state {
	for c := 0; c < 4; c++ {
		a := [4]byte{s[0][c], s[1][c], s[2][c], s[3][c]}
		s[0][c] = gmul(a[0],2)^gmul(a[1],3)^a[2]^a[3]
		s[1][c] = a[0]^gmul(a[1],2)^gmul(a[2],3)^a[3]
		s[2][c] = a[0]^a[1]^gmul(a[2],2)^gmul(a[3],3)
		s[3][c] = gmul(a[0],3)^a[1]^a[2]^gmul(a[3],2)
	}
	return s
}

func invMixColumns(s state) state {
	for c := 0; c < 4; c++ {
		a := [4]byte{s[0][c], s[1][c], s[2][c], s[3][c]}
		s[0][c] = gmul(a[0],0x0e)^gmul(a[1],0x0b)^gmul(a[2],0x0d)^gmul(a[3],0x09)
		s[1][c] = gmul(a[0],0x09)^gmul(a[1],0x0e)^gmul(a[2],0x0b)^gmul(a[3],0x0d)
		s[2][c] = gmul(a[0],0x0d)^gmul(a[1],0x09)^gmul(a[2],0x0e)^gmul(a[3],0x0b)
		s[3][c] = gmul(a[0],0x0b)^gmul(a[1],0x0d)^gmul(a[2],0x09)^gmul(a[3],0x0e)
	}
	return s
}

func addRoundKey(s state, rk []byte) state {
	for c := 0; c < 4; c++ {
		for r := 0; r < 4; r++ {
			s[r][c] ^= rk[c*4+r]
		}
	}
	return s
}

// ─────────────────────────────────────────────
// Key Expansion
// ─────────────────────────────────────────────

func keyExpansion(key []byte) ([][]byte, int) {
	nk := len(key) / 4
	nr := nk + 6

	w := make([][]byte, 4*(nr+1))
	for i := 0; i < nk; i++ {
		w[i] = key[i*4 : (i+1)*4]
	}
	for i := nk; i < 4*(nr+1); i++ {
		temp := make([]byte, 4)
		copy(temp, w[i-1])
		if i%nk == 0 {
			temp = []byte{sbox[temp[1]]^rcon[i/nk-1], sbox[temp[2]], sbox[temp[3]], sbox[temp[0]]}
		} else if nk > 6 && i%nk == 4 {
			for j := range temp { temp[j] = sbox[temp[j]] }
		}
		w[i] = make([]byte, 4)
		for j := 0; j < 4; j++ { w[i][j] = w[i-nk][j] ^ temp[j] }
	}

	// Convert words to 16-byte round keys (column-major)
	rks := make([][]byte, nr+1)
	for rnd := 0; rnd <= nr; rnd++ {
		rk := make([]byte, 16)
		for c := 0; c < 4; c++ {
			copy(rk[c*4:], w[rnd*4+c])
		}
		rks[rnd] = rk
	}
	return rks, nr
}

// ─────────────────────────────────────────────
// AES block encrypt/decrypt
// ─────────────────────────────────────────────

func aesEncryptBlock(block []byte, rks [][]byte, nr int) []byte {
	s := bytesToState(block)
	s = addRoundKey(s, rks[0])
	for rnd := 1; rnd < nr; rnd++ {
		s = subBytes(s)
		s = shiftRows(s)
		s = mixColumns(s)
		s = addRoundKey(s, rks[rnd])
	}
	s = subBytes(s)
	s = shiftRows(s)
	s = addRoundKey(s, rks[nr])
	return stateToBytes(s)
}

func aesDecryptBlock(block []byte, rks [][]byte, nr int) []byte {
	s := bytesToState(block)
	s = addRoundKey(s, rks[nr])
	for rnd := nr - 1; rnd >= 1; rnd-- {
		s = invShiftRows(s)
		s = invSubBytes(s)
		s = addRoundKey(s, rks[rnd])
		s = invMixColumns(s)
	}
	s = invShiftRows(s)
	s = invSubBytes(s)
	s = addRoundKey(s, rks[0])
	return stateToBytes(s)
}

func pkcs7Pad(data []byte) []byte {
	p := 16 - len(data)%16
	return append(data, []byte(strings.Repeat(string(rune(p)), p))...)
}

func pkcs7Unpad(data []byte) []byte {
	p := int(data[len(data)-1])
	return data[:len(data)-p]
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a { out[i] = a[i] ^ b[i] }
	return out
}

// AES is the public entry point for the AES algorithm.
func AES(operation string, params map[string]string) (map[string]string, error) {
	op := strings.ToLower(operation)

	switch op {
	case "encrypt":
		pt := []byte(params["plaintext"])
		keySize := 16 // default AES-128
		if params["key_size"] == "192" { keySize = 24 }
		if params["key_size"] == "256" { keySize = 32 }

		key := make([]byte, keySize)
		if _, err := rand.Read(key); err != nil { return nil, err }
		iv := make([]byte, 16)
		if _, err := rand.Read(iv); err != nil { return nil, err }

		rks, nr := keyExpansion(key)

		padded := pkcs7Pad(pt)
		ct := make([]byte, 0, len(padded))
		prev := iv
		for i := 0; i < len(padded); i += 16 {
			block := xorBytes(padded[i:i+16], prev)
			enc := aesEncryptBlock(block, rks, nr)
			ct = append(ct, enc...)
			prev = enc
		}

		var rkLines []string
		for i, rk := range rks {
			rkLines = append(rkLines, fmt.Sprintf("Round %2d: %s", i, strings.ToUpper(hex.EncodeToString(rk))))
		}

		return map[string]string{
			"key_hex":    strings.ToUpper(hex.EncodeToString(key)),
			"key_size":   fmt.Sprintf("AES-%d", keySize*8),
			"iv_hex":     strings.ToUpper(hex.EncodeToString(iv)),
			"ciphertext": strings.ToUpper(hex.EncodeToString(ct)),
			"round_keys": strings.Join(rkLines, "\n"),
			"rounds":     fmt.Sprintf("%d", nr),
			"mode":       "CBC",
		}, nil

	case "decrypt":
		ct, err := hex.DecodeString(params["ciphertext"])
		if err != nil { return nil, fmt.Errorf("invalid ciphertext hex: %w", err) }
		key, err := hex.DecodeString(params["key"])
		if err != nil { return nil, fmt.Errorf("invalid key hex: %w", err) }
		iv, err := hex.DecodeString(params["iv"])
		if err != nil { return nil, fmt.Errorf("invalid iv hex: %w", err) }

		rks, nr := keyExpansion(key)
		pt := make([]byte, 0, len(ct))
		prev := iv
		for i := 0; i < len(ct); i += 16 {
			block := ct[i : i+16]
			dec := aesDecryptBlock(block, rks, nr)
			pt = append(pt, xorBytes(dec, prev)...)
			prev = block
		}
		return map[string]string{"plaintext": string(pkcs7Unpad(pt))}, nil

	default:
		return nil, fmt.Errorf("unknown operation %q for AES", operation)
	}
}

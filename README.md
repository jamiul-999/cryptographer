# Cryptographer

Cryptographer is a full terminal UI application built to demonstrate classical and modern cryptographic algorithms side-by-side using Go and Python backends.

## Features

- **TUI Interface**: A btop-inspired, animated, and interactive TUI built with Lip Gloss.
- **Dual Backends**: Execute cryptography operations using native Go code or Python subprocesses.
- **Comparison Mode**: Run both Go and Python side-by-side to benchmark execution time and output parity.
- **Algorithms**:
  - Substitution Cipher (with Frequency Analysis & Brute Force)
  - Double Transposition Cipher
  - DES (Data Encryption Standard)
  - AES-128/192/256
  - RSA (with Key Generation & Pollard's Rho Factorization Attack)
  - ECC / ECDH (Elliptic Curve Cryptography)

## Installation

Ensure you have Go 1.22+ installed and Python 3.

```bash
# Clone the repository
git clone https://github.com/your-username/cryptographer.git
cd cryptographer

# Install dependencies
go mod tidy

# Build the project
make build

# Run the TUI
./cryptographer
```



## Architecture

- **Go Backend**: Algorithms are written from scratch in `internal/engine/`. No external cryptographic libraries are used.
- **Python Backend**: Algorithms are written from scratch in `py/`. Handled via a JSON bridge in `internal/bridge/`.
- **UI**: Handled entirely in `internal/tui/` with Bubble Tea.

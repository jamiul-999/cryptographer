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
  - RSA 
  - ECC / ECDH (Elliptic Curve Cryptography and Deffie Hellman)

## Installation

Ensure you have Go 1.22+ installed and Python 3.

```bash
# Clone the repository
git clone https://github.com/jamiul-999/cryptographer.git
cd cryptographer

# Install dependencies
go mod tidy

# Build the project (Linux/macOS)
make build

# Build the project (Windows)
go build -o cryptographer.exe ./cmd/cryptographer

# Run the TUI
## Linux/macOS
./cryptographer

## Windows
./cryptographer.exe
# OR run without building:
go run ./cmd/cryptographer
```

## Usage

When the application opens, use the following keys:
- `↑` / `↓` : Navigate algorithms
- `Enter` : Select algorithm or operation
- `Tab` : Navigate input form fields
- `Ctrl+S` : Toggle settings panel
- `F1` : Toggle help modal
- `Ctrl+C` : Quit

## Settings

- **Backend**: Choose between `go`, `python`, or `both` (Comparison Mode).


## Architecture

- **Go Backend**: Algorithms are written from scratch in `internal/engine/`. No external cryptographic libraries are used.
- **Python Backend**: Algorithms are written from scratch in `py/`. Handled via a JSON bridge in `internal/bridge/`.
- **UI**: Handled entirely in `internal/tui/` with Bubble Tea.

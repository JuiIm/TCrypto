# TCrypto — Hybrid Image Encryption (RSA + AES)

## Requirements

- GCC (MinGW or WSL)
- OpenSSL (`libssl`, `libcrypto`)
- Python 3 with `numpy`, `matplotlib`, `pillow` (for analysis only)

## Quick Start

```bash
# Build and run all 3 encryption tasks (Raw RSA, RSA+OAEP, Hybrid AES)
make run

# Build and run the custom-key demo
make test

# Clean build artifacts
make clean
```

## What `make run` Does

Reads an input image, generates a 1024-bit RSA key, then runs:

1. **Task 1** — Raw RSA block-by-block encryption/decryption
2. **Task 2** — RSA + OAEP (semantic security)
3. **Task 3** — Hybrid: RSA+OAEP wraps a random AES-256 key, AES-CBC encrypts the image

Both PNG (file bytes) and BMP (raw pixels) are processed. Results go to `output_*/`:

- `performance.csv` — timing data
- `bmp_task*_encrypted.bmp` — encrypted images for visual inspection
- `bmp_task*_decrypted.bmp` — decrypted roundtrip verification

> **Note:** Tasks 1–2 on large images are slow (minutes to hours). Task 3 finishes in milliseconds.

## What `make test` Does

Generates an RSA key, exports the primes as hex strings, rebuilds the key from those hex strings using `rsa_key_from_hex()`, and verifies encryption/decryption still works. Demonstrates how to use a custom key instead of generating one.

## Analysis (Python)

After `make run`, generate security metrics and plots:

```bash
python scripts/analyze.py output_colored
python scripts/analyze.py output_blackandwhite
```

Produces `metrics.csv` and `plots/` (histograms, entropy, correlation, etc.).

## Report

```bash
typst compile --root . docs/report.typ
```

## Project Structure

```
src/
  bignum.c      — Arbitrary-precision arithmetic (hand-implemented)
  rsa.c         — RSA keygen, encrypt/decrypt with CRT
  oaep.c        — OAEP padding (SHA-256 + MGF1)
  aes_cbc.c     — AES-256-CBC wrapper (OpenSSL)
  bmp_io.c      — BMP image reader/writer
  main.c        — Benchmark runner (make run)
  demo_custom_key.c — Custom key demo (make test)

include/        — Header files for each module
scripts/        — Python analysis scripts
docs/           — Typst report source
```

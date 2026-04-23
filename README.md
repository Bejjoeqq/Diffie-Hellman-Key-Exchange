# Diffie-Hellman Key Exchange (Tkinter Demo)

This project demonstrates the **Diffie-Hellman key exchange** algorithm using a desktop GUI built with Python and Tkinter.
It allows two parties to generate public keys, derive a shared symmetric key, hash that key with SHA-256, and observe an avalanche-effect metric.

## Features

- Diffie-Hellman key exchange simulation between Party A and Party B
- Configurable `g` (generator) and `p` (prime) values
- Optional built-in 2048-bit prime mode
- Display of:
  - Shared symmetric key
  - SHA-256 hash of the shared key
  - Both generated public keys
- Avalanche-effect rate display for generated values
- Batch/randomized run mode (`Range(500)`) to observe repeated trials

## Project Structure

```text
DiffieHellman.py   # Main GUI app and Diffie-Hellman implementation
```

## Requirements

- Python 3.8+
- Tkinter (usually bundled with standard Python installations)

## How to Run

From the repository root:

```bash
python DiffieHellman.py
```

## GUI Workflow

1. Enter **Private Key A** and **Private Key B**.
2. Either:
   - Keep manual `g` and `p` (spin boxes), or
   - Enable the large-prime mode checkbox (shown in the current GUI with label **`2 < (2048-bit)`**) to use the built-in 2048-bit prime (`p`) and generator `g = 2`.
3. Click **Generate** to compute:
   - Shared symmetric key
   - SHA-256 hash
   - Public keys for both parties
4. Optionally click **Range(500)** to run repeated calculations and observe rate/counter metrics.
5. Click **Reset** to clear values and counters.

## Core Components

### `DiffieHellman` class

- Stores key parameters (`g`, `p`) and private secret
- Generates public key with modular exponentiation
- Generates shared key from the other party’s public key
- Returns both raw shared key and its SHA-256 hash

### `AvalancheEffect` class

- Compares two values at bit level
- Computes the ratio of differing bits as a simple avalanche-effect metric

### `Gui` class

- Implements the full Tkinter user interface and interactions
- Manages user input, generated outputs, and aggregate rate statistics

## Notes and Limitations

- This repository is an educational/demo implementation, not a production cryptographic library.
- The GUI expects valid integer key inputs.
- Despite its name, `check_other_public_key` currently only checks `gcd(p, g) == 1` and does not validate the peer public key value itself.  
  This incomplete validation can enable weak or malicious public-key inputs, so this implementation is **not suitable for security-sensitive or production cryptographic use**.
- The application references `favicon.ico`; if missing on your platform, window icon loading may fail.

## Educational Purpose

Use this project to understand the mechanics of Diffie-Hellman exchange and how small input differences can affect derived outputs.
For real-world cryptography, use well-maintained, security-reviewed libraries.

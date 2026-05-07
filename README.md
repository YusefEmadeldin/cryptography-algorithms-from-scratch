# 🔐 CryptoLab

An interactive web application for exploring and visualizing cryptographic algorithms, built with **Python (Flask)**. Each algorithm is implemented **from scratch** — no external crypto libraries — and includes step-by-step breakdowns to illustrate how the computations work internally.

---

## ✨ Features

| Category | Algorithm | Description |
|---|---|---|
| **Hashing** | MD5 | 128-bit hash (RFC 1321) |
| **Hashing** | SHA-1 | 160-bit hash (FIPS 180-4) |
| **Hashing** | SHA-256 | 256-bit hash (FIPS 180-4) |
| **Key Derivation** | Bcrypt | Adaptive-cost password hashing based on Blowfish |
| **Public-Key Encryption** | ElGamal | Encryption scheme based on the Discrete Logarithm Problem |
| **Public-Key Cryptography** | ECC | Elliptic Curve key generation, point addition & scalar multiplication |

-  **Step-by-step visualization** — see intermediate values, round details, and final output for every operation.
-  **Interactive UI** — enter inputs and get instant results through a sleek dark-mode interface.
-  **Presets** — pre-configured parameter sets for ElGamal and ECC to get started quickly.
-  **Bcrypt verify** — hash a password *and* verify it against an existing hash.

---

##  Project Structure

```
cryptography project/
├── app.py                  # Flask application & API routes
├── requirements.txt        # Python dependencies
├── crypto/                 # Algorithm implementations (from scratch)
│   ├── __init__.py
│   ├── md5.py              # MD5 hash
│   ├── sha1.py             # SHA-1 hash
│   ├── sha256.py           # SHA-256 hash
│   ├── bcrypt_hash.py      # Bcrypt (Blowfish-based KDF)
│   ├── elgamal.py          # ElGamal encryption / decryption
│   └── ecc.py              # Elliptic Curve Cryptography
├── templates/
│   └── index.html          # Single-page frontend
└── static/
    ├── styles.css           # UI styles (dark theme)
    └── app.js               # Frontend logic & API calls
```

---

##  Getting Started

### Prerequisites

- **Python 3.8+**

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd "cryptography project"
   ```

2. **Create a virtual environment** *(recommended)*

   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS / Linux
   source venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**

   ```bash
   python app.py
   ```

5. **Open your browser** at [http://localhost:5000](http://localhost:5000)

---

## 🔌 API Endpoints

All endpoints accept **POST** requests with JSON bodies and return JSON responses.

### Hashing

| Endpoint | Body | Returns |
|---|---|---|
| `/api/md5` | `{ "message": "hello" }` | `{ "hash": "...", "steps": [...] }` |
| `/api/sha1` | `{ "message": "hello" }` | `{ "hash": "...", "steps": [...] }` |
| `/api/sha256` | `{ "message": "hello" }` | `{ "hash": "...", "steps": [...] }` |

### Bcrypt

| Endpoint | Body | Returns |
|---|---|---|
| `/api/bcrypt/hash` | `{ "password": "...", "cost": 10 }` | `{ "hash": "...", "steps": [...], "elapsed": ... }` |
| `/api/bcrypt/verify` | `{ "password": "...", "hash": "$2b$..." }` | `{ "match": true/false, "steps": [...] }` |

### ElGamal

| Endpoint | Body | Returns |
|---|---|---|
| `/api/elgamal/keygen` | `{ "q": 23, "alpha": 5 }` | Public/private keys + steps |
| `/api/elgamal/encrypt` | `{ "plaintext": 15, "q": 23, "alpha": 5, "y": ... }` | `{ "C1": ..., "C2": ..., "steps": [...] }` |
| `/api/elgamal/decrypt` | `{ "C1": ..., "C2": ..., "x": ..., "q": 23 }` | `{ "plaintext": ..., "steps": [...] }` |

### ECC

| Endpoint | Body | Returns |
|---|---|---|
| `/api/ecc/keygen` | `{ "a": 2, "b": 3, "p": 97, "gx": 3, "gy": 6 }` | Keys, curve points, order + steps |
| `/api/ecc/add` | `{ "a": 2, "p": 97, "p1x": ..., "p1y": ..., "p2x": ..., "p2y": ... }` | Result point |

---

##  Algorithm Details

### MD5 (RFC 1321)
Pads the message to 512-bit blocks, initializes four 32-bit registers (A-D), and processes each block through **4 rounds × 16 operations** using auxiliary functions F, G, H, I with pre-computed sine-table constants.

### SHA-1 (FIPS 180-4)
Similar padding with big-endian length. Five 32-bit registers (H0-H4), message schedule expanded from 16 → 80 words, and **80 rounds** using Ch, Parity, and Maj functions.

### SHA-256 (FIPS 180-4)
Eight 32-bit registers initialized from the square roots of the first 8 primes. Uses 64 round constants from cube roots of the first 64 primes, with Σ₀, Σ₁, σ₀, σ₁, Ch, and Maj functions across **64 rounds**.

### Bcrypt
Derives a Blowfish key schedule using the password and a 128-bit salt, then iterates `2^cost` rounds of key expansion (EksBlowfish). Encrypts the magic string `"OrpheanBeholderScryDoubt"` 64 times to produce the final hash.

### ElGamal
Generates keys over ℤ*_q using a prime `q` and primitive root `α`. Encrypts by choosing a random `k` and computing `(C1, C2) = (αᵏ mod q, M·yᵏ mod q)`. Decrypts via modular inverse of `C1ˣ`.

### ECC (Elliptic Curve Cryptography)
Operates on the curve `y² = x³ + ax + b (mod p)`. Supports point addition, doubling, and scalar multiplication (double-and-add). Key generation picks a random scalar `d` and computes the public key `Q = d·G`.

---

##  Tech Stack

- **Backend:** Python 3 / Flask
- **Frontend:** HTML, CSS, JavaScript (vanilla)
- **Crypto:** All algorithms implemented from scratch — zero external cryptography dependencies


#  CryptoLab

An interactive web application for exploring and visualizing cryptographic algorithms, built with **Python (Flask)**. Each algorithm is implemented **from scratch** — no external crypto libraries — and includes step-by-step breakdowns to illustrate how the computations work internally.

---

##  Features

| Category | Algorithm | Description |
|---|---|---|
| **Hashing** | MD5 | 128-bit hash (RFC 1321) |
| **Hashing** | SHA-1 | 160-bit hash (FIPS 180-4) |
| **Hashing** | SHA-256 | 256-bit hash (FIPS 180-4) |
| **Key Derivation** | Bcrypt | Adaptive-cost password hashing based on Blowfish |
| **Public-Key Encryption** | ElGamal | String-based encryption, decryption, and SHA-256 digital signatures |
| **Public-Key Cryptography** | ECC | Elliptic Curve keygen, text encryption, ECDSA signatures, supporting massive curves like secp256r1 |

-  **Step-by-step visualization** — see intermediate values, round details, and final output for every operation.
-  **Interactive UI** — enter inputs and get instant results through a sleek dark-mode interface.
-  **Presets** — pre-configured parameter sets for ElGamal and ECC (including NIST P-256 and Bitcoin secp256k1) to get started quickly.
-  **Bcrypt verify** — hash a password *and* verify it against an existing hash.
-  **Digital Signatures** — Sign and verify messages securely using ElGamal and ECDSA.

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

##  API Endpoints

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
| `/api/elgamal/keygen` | `{ "q": 479, "alpha": 13 }` | Public/private keys + steps |
| `/api/elgamal/encrypt` | `{ "plaintext": "Hello", "q": 479, "alpha": 13, "y": ... }` | `{ "ciphertext": [...], "steps": [...] }` |
| `/api/elgamal/decrypt` | `{ "ciphertext": [...], "x": ..., "q": 479 }` | `{ "plaintext": "Hello", "steps": [...] }` |
| `/api/elgamal/sign` | `{ "message": "Hello", "q": 479, "alpha": 13, "x": ... }` | `{ "S1": ..., "S2": ..., "steps": [...] }` |
| `/api/elgamal/verify` | `{ "message": "Hello", "q": 479, "alpha": 13, "y": ..., "S1": ..., "S2": ... }` | `{ "valid": true/false, "steps": [...] }` |

### ECC

| Endpoint | Body | Returns |
|---|---|---|
| `/api/ecc/keygen` | `{ "a": "...", "b": "...", "p": "...", "gx": "...", "gy": "...", "n": "..." }` | Keys, curve points, order + steps |
| `/api/ecc/encrypt` | `{ "plaintext": "Hello", "a": "...", "b": "...", "p": "...", "qx": "...", "qy": "..." }` | `{ "ciphertext": [...], "steps": [...] }` |
| `/api/ecc/decrypt` | `{ "ciphertext": [...], "a": "...", "p": "...", "d": "..." }` | `{ "plaintext": "Hello", "steps": [...] }` |
| `/api/ecc/sign` | `{ "message": "Hello", "d": "...", "n": "..." }` | `{ "r": "...", "s": "...", "steps": [...] }` |
| `/api/ecc/verify` | `{ "message": "Hello", "r": "...", "s": "...", "qx": "...", "qy": "..." }` | `{ "valid": true/false, "steps": [...] }` |

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
Generates keys over ℤ*_q using a prime `q` and primitive root `α`. Encrypts text character-by-character by choosing a random `k` and computing `(C1, C2) = (αᵏ mod q, M·yᵏ mod q)`. Decrypts via modular inverse of `C1ˣ`. Also supports digital signatures by hashing the message with SHA-256 and generating a pair `(S1, S2)` verified via `y^S1 · S1^S2 ≡ α^H(m) mod q`.

### ECC (Elliptic Curve Cryptography)
Operates on the curve `y² = x³ + ax + b (mod p)`. Supports standard curves (like `secp256r1` and `secp256k1`) using massive string-based integers. Encrypts text character-by-character into ElGamal-style point pairs `(C1, C2) = (k·G, M + k·Q)`. Features ECDSA signing and verification, deriving `(r,s)` using a random `k` and SHA-256 hash. Dynamically switches to abstract continuous curve visualizations for 256-bit industrial curves.

---

##  Tech Stack

- **Backend:** Python 3 / Flask
- **Frontend:** HTML, CSS, JavaScript (vanilla)
- **Crypto:** All algorithms implemented from scratch — zero external cryptography dependencies


"""
SHA-256 Hash Implementation (FIPS 180-4)
Produces a 256-bit (32-byte) hash value as a 64-char hex string.

Algorithm Steps:
1. Pad message to multiple of 512 bits (big-endian length)
2. Initialize 8 registers H0-H7 (fractional parts of sqrt of first 8 primes)
3. Use 64 round constants K (fractional parts of cbrt of first 64 primes)
4. Expand 16 words to 64 using sigma0, sigma1 functions
5. Process 64 rounds using Sigma0, Sigma1, Ch, Maj functions
6. Output concatenated registers as hex
"""

# 64 round constants: first 32 bits of fractional parts of cube roots of first 64 primes
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def _mask(x):
    return x & 0xFFFFFFFF


def _rotr(x, n):
    return _mask((x >> n) | (x << (32 - n)))


def _shr(x, n):
    return x >> n


def _ch(x, y, z):
    return _mask((x & y) ^ ((~x) & z))


def _maj(x, y, z):
    return _mask((x & y) ^ (x & z) ^ (y & z))


def _sigma0(x):
    return _mask(_rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22))


def _sigma1(x):
    return _mask(_rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25))


def _lsigma0(x):
    return _mask(_rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3))


def _lsigma1(x):
    return _mask(_rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10))


def _string_to_bytes(s):
    return list(s.encode('utf-8'))


def _pad(byte_list):
    msg = list(byte_list)
    bit_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg.extend([0, 0, 0, 0])
    msg.append((bit_len >> 24) & 0xFF)
    msg.append((bit_len >> 16) & 0xFF)
    msg.append((bit_len >> 8) & 0xFF)
    msg.append(bit_len & 0xFF)
    return msg


def hash_sha256(message):
    """Compute SHA-256 hash. Returns 64-char hex string."""
    return hash_sha256_with_steps(message)['hash']


def hash_sha256_with_steps(message):
    """Compute SHA-256 hash with step-by-step details."""
    msg_bytes = _pad(_string_to_bytes(message))
    steps = []

    # Initial hash values: fractional parts of sqrt of first 8 primes
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    steps.append(f"Initialize H0-H7 from fractional parts of √(first 8 primes)")
    steps.append(f"Padded to {len(msg_bytes) * 8} bits ({len(msg_bytes) // 64} block(s))")

    num_blocks = len(msg_bytes) // 64

    for block in range(num_blocks):
        offset = block * 64
        W = [0] * 64

        for i in range(16):
            W[i] = _mask(
                (msg_bytes[offset + i * 4] << 24) |
                (msg_bytes[offset + i * 4 + 1] << 16) |
                (msg_bytes[offset + i * 4 + 2] << 8) |
                msg_bytes[offset + i * 4 + 3]
            )

        # Message schedule expansion
        for i in range(16, 64):
            W[i] = _mask(_lsigma1(W[i - 2]) + W[i - 7] + _lsigma0(W[i - 15]) + W[i - 16])

        a, b, c, d, e, f, g, h = H

        for i in range(64):
            # T1 combines the h register, Sigma1(e), Choice(e,f,g), Round Constant, and Word
            T1 = _mask(h + _sigma1(e) + _ch(e, f, g) + K[i] + W[i])
            # T2 combines Sigma0(a) and Majority(a,b,c)
            T2 = _mask(_sigma0(a) + _maj(a, b, c))
            
            # Shift registers down
            h = g
            g = f
            f = e
            # Add T1 to d to create new e
            e = _mask(d + T1)
            d = c
            c = b
            b = a
            # New a is T1 + T2
            a = _mask(T1 + T2)

        H[0] = _mask(H[0] + a)
        H[1] = _mask(H[1] + b)
        H[2] = _mask(H[2] + c)
        H[3] = _mask(H[3] + d)
        H[4] = _mask(H[4] + e)
        H[5] = _mask(H[5] + f)
        H[6] = _mask(H[6] + g)
        H[7] = _mask(H[7] + h)

        steps.append(f"Block {block + 1}/{num_blocks}: 64 rounds with Σ0, Σ1, Ch, Maj functions")

    def to_hex(n):
        return format(n, '08x')

    hash_value = ''.join(to_hex(v) for v in H)

    steps.append(f"Final hash: {hash_value}")
    return {'hash': hash_value, 'steps': steps}


def hash_sha256_bytes_with_steps(byte_data):
    """Compute SHA-256 hash from raw bytes (for file uploads)."""
    msg_bytes = _pad(list(byte_data))
    steps = []

    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    steps.append(f"Initialize H0-H7 from fractional parts of √(first 8 primes)")
    steps.append(f"File size: {len(byte_data)} bytes")
    steps.append(f"Padded to {len(msg_bytes) * 8} bits ({len(msg_bytes) // 64} block(s))")

    num_blocks = len(msg_bytes) // 64

    for block in range(num_blocks):
        offset = block * 64
        W = [0] * 64

        for i in range(16):
            W[i] = _mask(
                (msg_bytes[offset + i * 4] << 24) |
                (msg_bytes[offset + i * 4 + 1] << 16) |
                (msg_bytes[offset + i * 4 + 2] << 8) |
                msg_bytes[offset + i * 4 + 3]
            )

        for i in range(16, 64):
            W[i] = _mask(_lsigma1(W[i - 2]) + W[i - 7] + _lsigma0(W[i - 15]) + W[i - 16])

        a, b, c, d, e, f, g, h = H

        for i in range(64):
            T1 = _mask(h + _sigma1(e) + _ch(e, f, g) + K[i] + W[i])
            T2 = _mask(_sigma0(a) + _maj(a, b, c))
            h = g
            g = f
            f = e
            e = _mask(d + T1)
            d = c
            c = b
            b = a
            a = _mask(T1 + T2)

        H[0] = _mask(H[0] + a)
        H[1] = _mask(H[1] + b)
        H[2] = _mask(H[2] + c)
        H[3] = _mask(H[3] + d)
        H[4] = _mask(H[4] + e)
        H[5] = _mask(H[5] + f)
        H[6] = _mask(H[6] + g)
        H[7] = _mask(H[7] + h)

    steps.append(f"Processed {num_blocks} block(s) — 64 rounds each")

    def to_hex(n):
        return format(n, '08x')

    hash_value = ''.join(to_hex(v) for v in H)

    steps.append(f"Final hash: {hash_value}")
    return {'hash': hash_value, 'steps': steps}

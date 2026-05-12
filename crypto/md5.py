"""
MD5 Hash Implementation (RFC 1321)
Produces a 128-bit (16-byte) hash value as a 32-char hex string.

Algorithm Steps:
1. Pad message to 448 mod 512 bits, append 64-bit length (little-endian)
2. Initialize 4 registers: A, B, C, D
3. Process each 512-bit block through 4 rounds of 16 operations
4. Output concatenated registers as hex
"""

import math

# T[i] = floor(2^32 * |sin(i + 1)|)
T = [0] * 64
for i in range(64):
    T[i] = int(abs(math.sin(i + 1)) * 0x100000000) & 0xFFFFFFFF

# Per-round shift amounts
S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]


def _mask(x):
    """Mask to 32-bit unsigned integer."""
    return x & 0xFFFFFFFF


def _rotl(x, n):
    """Rotate left 32-bit."""
    return _mask((x << n) | (x >> (32 - n)))


def _string_to_bytes(s):
    """Convert a string to a list of bytes."""
    return list(s.encode('utf-8'))


def _pad(byte_list):
    """Pad the message to a multiple of 512 bits."""
    msg = list(byte_list)
    original_bit_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    # Append original length as 64-bit little-endian
    for i in range(8):
        msg.append((original_bit_len >> (i * 8)) & 0xFF)
    return msg


def hash_md5(message):
    """Compute MD5 hash of a message string. Returns 32-char hex string."""
    return hash_md5_with_steps(message)['hash']


def hash_md5_with_steps(message):
    """Compute MD5 hash with step-by-step details."""
    msg_bytes = _pad(_string_to_bytes(message))
    steps = []

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    steps.append(f"Initialize MD buffer: A={a0:#010x}, B={b0:#010x}, C={c0:#010x}, D={d0:#010x}")
    steps.append(f"Message padded to {len(msg_bytes) * 8} bits ({len(msg_bytes) // 64} block(s))")

    num_blocks = len(msg_bytes) // 64

    for block in range(num_blocks):
        offset = block * 64
        M = [0] * 16
        for i in range(16):
            M[i] = (msg_bytes[offset + i * 4] |
                     (msg_bytes[offset + i * 4 + 1] << 8) |
                     (msg_bytes[offset + i * 4 + 2] << 16) |
                     (msg_bytes[offset + i * 4 + 3] << 24))
            M[i] = _mask(M[i])

        A, B, C, D = a0, b0, c0, d0

        for i in range(64):
            if i < 16:
                # Round 1: F(B, C, D) = (B & C) | (~B & D) - nonlinear function
                F = (B & C) | ((~B) & D)
                g = i
                round_name = 'F'
            elif i < 32:
                # Round 2: G(B, C, D) = (B & D) | (C & ~D)
                F = (D & B) | ((~D) & C)
                g = (5 * i + 1) % 16
                round_name = 'G'
            elif i < 48:
                # Round 3: H(B, C, D) = B ^ C ^ D (XOR parity)
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
                round_name = 'H'
            else:
                # Round 4: I(B, C, D) = C ^ (B | ~D)
                F = C ^ (B | (~D))
                g = (7 * i) % 16
                round_name = 'I'
            F = _mask(F)

            temp = D
            D = C
            C = B
            B = _mask(B + _rotl(_mask(A + F + T[i] + M[g]), S[i]))
            A = temp

        a0 = _mask(a0 + A)
        b0 = _mask(b0 + B)
        c0 = _mask(c0 + C)
        d0 = _mask(d0 + D)

        steps.append(f"Block {block + 1}/{num_blocks}: Processed 64 operations (F, G, H, I rounds)")

    def to_le_hex(n):
        h = ''
        for i in range(4):
            h += format((n >> (i * 8)) & 0xFF, '02x')
        return h

    hash_value = to_le_hex(a0) + to_le_hex(b0) + to_le_hex(c0) + to_le_hex(d0)

    steps.append(f"Final hash: {hash_value}")
    return {'hash': hash_value, 'steps': steps}


def hash_md5_bytes_with_steps(byte_data):
    """Compute MD5 hash from raw bytes (for file uploads)."""
    msg_bytes = _pad(list(byte_data))
    steps = []

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    steps.append(f"Initialize MD buffer: A={a0:#010x}, B={b0:#010x}, C={c0:#010x}, D={d0:#010x}")
    steps.append(f"File size: {len(byte_data)} bytes")
    steps.append(f"Message padded to {len(msg_bytes) * 8} bits ({len(msg_bytes) // 64} block(s))")

    num_blocks = len(msg_bytes) // 64

    for block in range(num_blocks):
        offset = block * 64
        M = [0] * 16
        for i in range(16):
            M[i] = (msg_bytes[offset + i * 4] |
                     (msg_bytes[offset + i * 4 + 1] << 8) |
                     (msg_bytes[offset + i * 4 + 2] << 16) |
                     (msg_bytes[offset + i * 4 + 3] << 24))
            M[i] = _mask(M[i])

        A, B, C, D = a0, b0, c0, d0

        for i in range(64):
            if i < 16:
                F = (B & C) | ((~B) & D)
                g = i
                round_name = 'F'
            elif i < 32:
                F = (D & B) | ((~D) & C)
                g = (5 * i + 1) % 16
                round_name = 'G'
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
                round_name = 'H'
            else:
                F = C ^ (B | (~D))
                g = (7 * i) % 16
                round_name = 'I'
            F = _mask(F)

            temp = D
            D = C
            C = B
            B = _mask(B + _rotl(_mask(A + F + T[i] + M[g]), S[i]))
            A = temp

        a0 = _mask(a0 + A)
        b0 = _mask(b0 + B)
        c0 = _mask(c0 + C)
        d0 = _mask(d0 + D)

    steps.append(f"Processed {num_blocks} block(s) — 64 operations each")

    def to_le_hex(n):
        h = ''
        for i in range(4):
            h += format((n >> (i * 8)) & 0xFF, '02x')
        return h

    hash_value = to_le_hex(a0) + to_le_hex(b0) + to_le_hex(c0) + to_le_hex(d0)

    steps.append(f"Final hash: {hash_value}")
    return {'hash': hash_value, 'steps': steps}

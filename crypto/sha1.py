"""
SHA-1 Hash Implementation (FIPS 180-4)
Produces a 160-bit (20-byte) hash value as a 40-char hex string.

Algorithm Steps:
1. Pad message to multiple of 512 bits (big-endian length)
2. Initialize 5 registers: H0-H4
3. Expand 16 words to 80 words per block
4. Process 80 rounds with Ch/Parity/Maj functions
5. Output concatenated registers as hex
"""


def _mask(x):
    return x & 0xFFFFFFFF


def _rotl(x, n):
    return _mask((x << n) | (x >> (32 - n)))


def _string_to_bytes(s):
    return list(s.encode('utf-8'))


def _pad(byte_list):
    msg = list(byte_list)
    bit_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    # Append length as 64-bit big-endian
    msg.extend([0, 0, 0, 0])
    msg.append((bit_len >> 24) & 0xFF)
    msg.append((bit_len >> 16) & 0xFF)
    msg.append((bit_len >> 8) & 0xFF)
    msg.append(bit_len & 0xFF)
    return msg


def hash_sha1(message):
    """Compute SHA-1 hash. Returns 40-char hex string."""
    return hash_sha1_with_steps(message)['hash']


def hash_sha1_with_steps(message):
    """Compute SHA-1 hash with step-by-step details."""
    msg_bytes = _pad(_string_to_bytes(message))
    steps = []

    H0 = 0x67452301
    H1 = 0xEFCDAB89
    H2 = 0x98BADCFE
    H3 = 0x10325476
    H4 = 0xC3D2E1F0

    steps.append(f"Initialize: H0={H0:#010x}, H1={H1:#010x}, H2={H2:#010x}, H3={H3:#010x}, H4={H4:#010x}")
    steps.append(f"Padded to {len(msg_bytes) * 8} bits ({len(msg_bytes) // 64} block(s))")

    num_blocks = len(msg_bytes) // 64

    for block in range(num_blocks):
        offset = block * 64
        W = [0] * 80

        for i in range(16):
            W[i] = _mask(
                (msg_bytes[offset + i * 4] << 24) |
                (msg_bytes[offset + i * 4 + 1] << 16) |
                (msg_bytes[offset + i * 4 + 2] << 8) |
                msg_bytes[offset + i * 4 + 3]
            )

        # Expand to 80 words
        for i in range(16, 80):
            W[i] = _rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1)

        a, b, c, d, e = H0, H1, H2, H3, H4

        for i in range(80):
            if i < 20:
                f = _mask((b & c) | ((~b) & d))
                k = 0x5A827999
            elif i < 40:
                f = _mask(b ^ c ^ d)
                k = 0x6ED9EBA1
            elif i < 60:
                f = _mask((b & c) | (b & d) | (c & d))
                k = 0x8F1BBCDC
            else:
                f = _mask(b ^ c ^ d)
                k = 0xCA62C1D6

            temp = _mask(_rotl(a, 5) + f + e + k + W[i])
            e = d
            d = c
            c = _rotl(b, 30)
            b = a
            a = temp

        H0 = _mask(H0 + a)
        H1 = _mask(H1 + b)
        H2 = _mask(H2 + c)
        H3 = _mask(H3 + d)
        H4 = _mask(H4 + e)

        steps.append(f"Block {block + 1}/{num_blocks}: 80 rounds (Ch 0-19, Parity 20-39, Maj 40-59, Parity 60-79)")

    def to_hex(n):
        return format(n, '08x')

    hash_value = to_hex(H0) + to_hex(H1) + to_hex(H2) + to_hex(H3) + to_hex(H4)

    steps.append(f"Final hash: {hash_value}")
    return {'hash': hash_value, 'steps': steps}


def hash_sha1_bytes_with_steps(byte_data):
    """Compute SHA-1 hash from raw bytes (for file uploads)."""
    msg_bytes = _pad(list(byte_data))
    steps = []

    H0 = 0x67452301
    H1 = 0xEFCDAB89
    H2 = 0x98BADCFE
    H3 = 0x10325476
    H4 = 0xC3D2E1F0

    steps.append(f"Initialize: H0={H0:#010x}, H1={H1:#010x}, H2={H2:#010x}, H3={H3:#010x}, H4={H4:#010x}")
    steps.append(f"File size: {len(byte_data)} bytes")
    steps.append(f"Padded to {len(msg_bytes) * 8} bits ({len(msg_bytes) // 64} block(s))")

    num_blocks = len(msg_bytes) // 64

    for block in range(num_blocks):
        offset = block * 64
        W = [0] * 80

        for i in range(16):
            W[i] = _mask(
                (msg_bytes[offset + i * 4] << 24) |
                (msg_bytes[offset + i * 4 + 1] << 16) |
                (msg_bytes[offset + i * 4 + 2] << 8) |
                msg_bytes[offset + i * 4 + 3]
            )

        for i in range(16, 80):
            W[i] = _rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1)

        a, b, c, d, e = H0, H1, H2, H3, H4

        for i in range(80):
            if i < 20:
                f = _mask((b & c) | ((~b) & d))
                k = 0x5A827999
            elif i < 40:
                f = _mask(b ^ c ^ d)
                k = 0x6ED9EBA1
            elif i < 60:
                f = _mask((b & c) | (b & d) | (c & d))
                k = 0x8F1BBCDC
            else:
                f = _mask(b ^ c ^ d)
                k = 0xCA62C1D6

            temp = _mask(_rotl(a, 5) + f + e + k + W[i])
            e = d
            d = c
            c = _rotl(b, 30)
            b = a
            a = temp

        H0 = _mask(H0 + a)
        H1 = _mask(H1 + b)
        H2 = _mask(H2 + c)
        H3 = _mask(H3 + d)
        H4 = _mask(H4 + e)

    steps.append(f"Processed {num_blocks} block(s) — 80 rounds each")

    def to_hex(n):
        return format(n, '08x')

    hash_value = to_hex(H0) + to_hex(H1) + to_hex(H2) + to_hex(H3) + to_hex(H4)

    steps.append(f"Final hash: {hash_value}")
    return {'hash': hash_value, 'steps': steps}

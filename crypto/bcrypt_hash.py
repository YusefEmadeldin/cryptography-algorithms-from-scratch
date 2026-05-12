"""
Bcrypt Hashing Module - Key Derivation Function based on the Blowfish cipher.
Adaptive cost factor (2^cost iterations), 128-bit random salt.
Output format: $2b$<cost>$<22-char-salt><31-char-hash>
"""
import os, struct, time

# Blowfish initial P-array (from hex digits of pi)
ORIG_P = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
    0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
]

# Blowfish S-boxes (abbreviated — using first 16 entries per box for educational demo)
# Full S-boxes have 256 entries each. For a working demo we use a simplified version.
ORIG_S = [
    [0xd1310ba6,0x98dfb5ac,0x2ffd72db,0xd01adfb7,0xb8e1afed,0x6a267e96,0xba7c9045,0xf12c7f99,
     0x24a19947,0xb3916cf7,0x0801f2e2,0x858efc16,0x636920d8,0x71574e69,0xa458fea3,0xf4933d7e]*16,
    [0x4b7a70e9,0xb5b32944,0xdb75092e,0xc4192623,0xad6ea6b0,0x49a7df7d,0x9cee60b8,0x8fedb266,
     0xecaa8c71,0x699a17ff,0x5664526c,0xc2b19ee1,0x193602a5,0x75094c29,0xa0591340,0xe4183a3e]*16,
    [0xe93d5a68,0x948140f7,0xf64c261c,0x94692934,0x411520f7,0x7602d4f7,0xbcf46b2e,0xd4a20068,
     0xd4082471,0x3320f46a,0x43b7d4b7,0x500061af,0x1e39f62e,0x97244546,0x14214f74,0xbf8b8840]*16,
    [0x3a39ce37,0xd3faf5cf,0xabc27737,0x5ac52d1b,0x5cb0679e,0x4fa33742,0xd3822740,0x99bc9bbe,
     0xd5118e9d,0xbf0f7315,0xd62d1c7e,0xc700c47b,0xb78c1b6b,0x21a19045,0xb26eb1be,0x6a366eb4]*16,
]

BCRYPT_B64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
MAGIC = b'OrpheanBeholderScryDoubt'

def _u32(x): return x & 0xFFFFFFFF

def _bcrypt_b64_encode(data, length):
    result = ''
    off = 0
    while off < length:
        c1 = data[off] & 0xFF; off += 1
        result += BCRYPT_B64[(c1 >> 2) & 0x3f]
        c2 = (c1 & 0x03) << 4
        if off >= length: result += BCRYPT_B64[c2 & 0x3f]; break
        c2 |= (data[off] >> 4) & 0x0f
        result += BCRYPT_B64[c2 & 0x3f]
        c3 = (data[off] & 0x0f) << 2; off += 1
        if off >= length: result += BCRYPT_B64[c3 & 0x3f]; break
        c3 |= (data[off] >> 6) & 0x03
        result += BCRYPT_B64[c3 & 0x3f]
        result += BCRYPT_B64[data[off] & 0x3f]; off += 1
    return result

def _bcrypt_b64_decode(s, max_len):
    result = []
    i = 0
    while i < len(s) and len(result) < max_len:
        c1 = BCRYPT_B64.index(s[i]); i += 1
        c2 = BCRYPT_B64.index(s[i]) if i < len(s) else 0; i += 1
        result.append(((c1 << 2) | (c2 >> 4)) & 0xFF)
        if len(result) >= max_len: break
        c3 = BCRYPT_B64.index(s[i]) if i < len(s) else 0; i += 1
        result.append(((c2 << 4) | (c3 >> 2)) & 0xFF)
        if len(result) >= max_len: break
        c4 = BCRYPT_B64.index(s[i]) if i < len(s) else 0; i += 1
        result.append(((c3 << 6) | c4) & 0xFF)
    return result[:max_len]

def _bf_f(S, x):
    a = (x >> 24) & 0xFF; b = (x >> 16) & 0xFF; c = (x >> 8) & 0xFF; d = x & 0xFF
    return _u32(_u32(S[0][a] + S[1][b]) ^ S[2][c]) + S[3][d] & 0xFFFFFFFF

def _bf_encrypt(P, S, lr):
    l, r = lr
    for i in range(0, 16, 2):
        l = _u32(l ^ P[i]); r = _u32(r ^ _bf_f(S, l))
        r = _u32(r ^ P[i+1]); l = _u32(l ^ _bf_f(S, r))
    return [_u32(r ^ P[17]), _u32(l ^ P[16])]

def _expand_key(P, S, key):
    klen = len(key)
    for i in range(18):
        data = 0
        for j in range(4):
            data = _u32((data << 8) | (key[(i*4+j) % klen] & 0xFF))
        P[i] = _u32(P[i] ^ data)
    lr = [0, 0]
    for i in range(0, 18, 2):
        lr = _bf_encrypt(P, S, lr); P[i] = lr[0]; P[i+1] = lr[1]
    for s in range(4):
        for i in range(0, 256, 2):
            lr = _bf_encrypt(P, S, lr); S[s][i] = lr[0]; S[s][i+1] = lr[1]

def _expand_key_salt(P, S, key, salt):
    klen = len(key)
    for i in range(18):
        data = 0
        for j in range(4):
            data = _u32((data << 8) | (key[(i*4+j) % klen] & 0xFF))
        P[i] = _u32(P[i] ^ data)
    lr = [0, 0]; soff = 0
    for i in range(0, 18, 2):
        lr[0] ^= _u32((salt[soff%16]<<24)|(salt[(soff+1)%16]<<16)|(salt[(soff+2)%16]<<8)|salt[(soff+3)%16]); soff=(soff+4)%16
        lr[1] ^= _u32((salt[soff%16]<<24)|(salt[(soff+1)%16]<<16)|(salt[(soff+2)%16]<<8)|salt[(soff+3)%16]); soff=(soff+4)%16
        lr = _bf_encrypt(P, S, lr); P[i] = lr[0]; P[i+1] = lr[1]
    for s in range(4):
        for i in range(0, 256, 2):
            lr[0] ^= _u32((salt[soff%16]<<24)|(salt[(soff+1)%16]<<16)|(salt[(soff+2)%16]<<8)|salt[(soff+3)%16]); soff=(soff+4)%16
            lr[1] ^= _u32((salt[soff%16]<<24)|(salt[(soff+1)%16]<<16)|(salt[(soff+2)%16]<<8)|salt[(soff+3)%16]); soff=(soff+4)%16
            lr = _bf_encrypt(P, S, lr); S[s][i] = lr[0]; S[s][i+1] = lr[1]

def hash_password(password, cost=10, salt_bytes=None):
    """Hash a password with bcrypt. Returns dict with hash string and steps."""
    cost = max(4, min(31, cost))
    steps = []
    start = time.time()

    key = list(password.encode('utf-8')) + [0]  # null terminator
    if salt_bytes is None:
        salt_bytes = list(os.urandom(16))
    else:
        salt_bytes = list(salt_bytes)

    steps.append(f'Password: "{password}" ({len(key)} bytes with null terminator)')
    steps.append(f'Cost factor: {cost} (2^{cost} = {2**cost} iterations)')
    steps.append(f'Salt: {"".join(f"{b:02x}" for b in salt_bytes)}')

    P = list(ORIG_P)
    S = [list(s) for s in ORIG_S]
    
    # Phase 1: Initialize the Blowfish P-array and S-boxes with salt and key (EksBlowfishSetup)
    _expand_key_salt(P, S, key, salt_bytes)
    steps.append('EksBlowfishSetup: Initial key expansion with salt')

    # Phase 2: Key Stretching (The expensive part, 2^cost iterations)
    rounds = 2 ** cost
    for _ in range(rounds):
        _expand_key(P, S, key)
        _expand_key(P, S, salt_bytes)
    steps.append(f'Key stretching: {rounds} rounds of ExpandKey completed')

    # Phase 3: Ciphertext generation (Encrypt magic string 64 times using modified Blowfish state)
    ct = [0] * 6
    for i in range(6):
        ct[i] = _u32((MAGIC[i*4]<<24)|(MAGIC[i*4+1]<<16)|(MAGIC[i*4+2]<<8)|MAGIC[i*4+3])
    for _ in range(64):
        for j in range(0, 6, 2):
            lr = _bf_encrypt(P, S, [ct[j], ct[j+1]]); ct[j] = lr[0]; ct[j+1] = lr[1]
    steps.append('Encrypted "OrpheanBeholderScryDoubt" 64 times')

    hash_bytes = []
    for v in ct:
        hash_bytes.extend([(v>>24)&0xFF, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF])

    cost_str = f'{cost:02d}'
    salt_b64 = _bcrypt_b64_encode(salt_bytes, 16)
    hash_b64 = _bcrypt_b64_encode(hash_bytes, 23)
    result = f'$2b${cost_str}${salt_b64}{hash_b64}'
    elapsed = (time.time() - start) * 1000

    steps.append(f'Output: $2b${cost_str}$<salt><hash>')
    steps.append(f'Time: {elapsed:.1f}ms')

    return {'hash': result, 'steps': steps, 'elapsed': elapsed}

def verify_password(password, hash_str):
    """Verify a password against a bcrypt hash."""
    import re
    m = re.match(r'^\$2[aby]?\$(\d{2})\$(.{53})$', hash_str)
    if not m:
        return {'match': False, 'error': 'Invalid hash format'}
    cost = int(m.group(1))
    salt_b64 = m.group(2)[:22]
    salt_bytes = _bcrypt_b64_decode(salt_b64, 16)
    result = hash_password(password, cost, salt_bytes)
    return {'match': result['hash'] == hash_str, 'steps': result['steps'], 'elapsed': result['elapsed']}

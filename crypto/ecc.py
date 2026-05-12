"""
Elliptic Curve Cryptography (ECC) Implementation
Curve: y² = x³ + ax + b (mod p), with 4a³ + 27b² ≠ 0 (non-singular)

Operations:
- Point Addition (P + Q)
- Point Doubling (2P)
- Scalar Multiplication (k·P) using double-and-add
- Key Generation: private key d, public key Q = d·G
"""
import random
import hashlib

def _mod(a, m):
    return ((a % m) + m) % m

def _mod_inverse(a, m):
    a = _mod(a, m)
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        return None
    return _mod(old_s, m)

def is_non_singular(a, b, p):
    return _mod(4 * a**3 + 27 * b**2, p) != 0

def is_on_curve(px, py, a, b, p):
    if px is None:
        return True
    return _mod(py * py, p) == _mod(px**3 + a * px + b, p)

def point_add(p1x, p1y, p2x, p2y, a, p):
    """Add two points. None coords = point at infinity."""
    if p1x is None: return p2x, p2y
    if p2x is None: return p1x, p1y
    if p1x == p2x and _mod(p1y + p2y, p) == 0:
        return None, None

    if p1x == p2x and p1y == p2y:
        num = _mod(3 * p1x * p1x + a, p)
        den = _mod_inverse(2 * p1y, p)
    else:
        num = _mod(p2y - p1y, p)
        den = _mod_inverse(_mod(p2x - p1x, p), p)

    if den is None:
        return None, None

    lam = _mod(num * den, p)
    xr = _mod(lam * lam - p1x - p2x, p)
    yr = _mod(lam * (p1x - xr) - p1y, p)
    return xr, yr

def scalar_mult(k, px, py, a, p):
    """Compute k * P using double-and-add."""
    if k == 0 or px is None:
        return None, None
    rx, ry = None, None
    ax, ay = px, py
    while k > 0:
        if k & 1:
            rx, ry = point_add(rx, ry, ax, ay, a, p)
        ax, ay = point_add(ax, ay, ax, ay, a, p)
        k >>= 1
    return rx, ry

def find_all_points(a, b, p):
    """Find all points on the curve (including infinity)."""
    points = [{'x': None, 'y': None}]
    for x in range(p):
        rhs = _mod(x**3 + a * x + b, p)
        for y in range(p):
            if _mod(y * y, p) == rhs:
                points.append({'x': x, 'y': y})
    return points

import math

def point_order(px, py, a, p):
    qx, qy = px, py
    # Hasse's Theorem: N <= p + 1 + 2*sqrt(p)
    limit = p + 1 + 2 * int(math.sqrt(p)) + 2
    for i in range(1, limit):
        if qx is None:
            return i
        qx, qy = point_add(qx, qy, px, py, a, p)
    return -1

PRESETS = [
    {
        'label': 'secp256r1 (NIST P-256)', 
        'a': '115792089210356248762697446949407573530086143415290314195533631308867097853948',
        'b': '41058363725152142129326129780047268409114441015993725554835256314039467401291',
        'p': '115792089210356248762697446949407573530086143415290314195533631308867097853951',
        'Gx': '48439561293906451759052585252797914202762949526041747995844080717082404635286',
        'Gy': '36134250956749795798585127919587881956611106672985015071877198253568414405109',
        'n': '115792089210356248762697446949407573529996955224135760342422259061068512044369'
    },
    {
        'label': 'secp256k1 (Bitcoin)',
        'a': '0',
        'b': '7',
        'p': '115792089237316195423570985008687907853269984665640564039457584007908834671663',
        'Gx': '55066263022277343669578718895168534326250603453777594175500187360389116729240',
        'Gy': '32670510020758816978083085130507043184471273380659243275938904335757337482424',
        'n': '115792089237316195423570985008687907852837564279074904382605163141518161494337'
    },
    {'a': 2, 'b': 3, 'p': 97, 'Gx': 3, 'Gy': 6, 'label': 'y²=x³+2x+3 mod 97, G=(3,6)'},
    {'a': 1, 'b': 1, 'p': 23, 'Gx': 0, 'Gy': 1, 'label': 'y²=x³+x+1 mod 23, G=(0,1)'},
    {'a': 2, 'b': 2, 'p': 17, 'Gx': 5, 'Gy': 1, 'label': 'y²=x³+2x+2 mod 17, G=(5,1)'},
    {'label': 'Invalid Curve 1 (Singular)', 'a': 0, 'b': 0, 'p': 97, 'Gx': 0, 'Gy': 0},
    {'label': 'Invalid Curve 2 (G not on curve)', 'a': 2, 'b': 3, 'p': 97, 'Gx': 1, 'Gy': 1},
]

def key_gen(a, b, p, gx, gy, n=None):
    steps = []
    if not is_non_singular(a, b, p):
        return {'error': 'Unsupported Curve. (Curve is singular 4a³+27b²≡0)'}
    if not is_on_curve(gx, gy, a, b, p):
        return {'error': 'Unsupported Curve. (Generator G is not on the curve)'}

    if n is None:
        if p > 10000:
            return {'error': 'p is too large to brute-force order n. Please provide n.'}
        n = point_order(gx, gy, a, p)
        
    d = random.randint(1, n - 1)
    qx, qy = scalar_mult(d, gx, gy, a, p)

    disc = _mod(4*a**3 + 27*b**2, p)
    steps.append(f'Curve: y² = x³ + a·x + b (mod p)')
    steps.append(f'4a³ + 27b² mod p = {disc} ≠ 0 ✓')
    steps.append(f'Generator G = ({gx}, {gy})')
    steps.append(f'Order of G: n = {n}')
    steps.append(f'Private key d (random, 1 ≤ d < n)')
    steps.append(f'Public key Q = d·G = ({qx}, {qy})')

    return {
        'private_key': str(d),
        'public_key': {'x': str(qx), 'y': str(qy)},
        'order': str(n),
        'steps': steps
    }


def point_neg(px, py, p):
    """Negate a point: -(x, y) = (x, p - y)."""
    if px is None:
        return None, None
    return px, _mod(-py, p)


def ecc_encrypt(plaintext_str, a, b, p, gx, gy, qx, qy, n):
    """
    Encrypt a plaintext string using ElGamal ECC.
    Each character m is encoded as M = m·G, then encrypted as (k·G, M + k·Q).
    """
    steps = []
    ciphertext = []

    if not plaintext_str:
        return {'error': 'Plaintext cannot be empty'}

    # Check all character codes fit within the generator order
    max_char = max(ord(ch) for ch in plaintext_str)
    if max_char >= n:
        return {'error': f'Character code {max_char} exceeds generator order n={n}. Use a larger curve (larger p).'}

    steps.append(f'Plaintext: "{plaintext_str}" ({len(plaintext_str)} chars)')
    steps.append(f'Curve: y² = x³ + a·x + b (mod p)')
    steps.append(f'Public key Q = ({qx}, {qy})')

    for i, ch in enumerate(plaintext_str):
        m = ord(ch)
        # M = m * G
        mx, my = scalar_mult(m, gx, gy, a, p)

        # Random k
        k = random.randint(1, n - 1)

        # C1 = k * G
        c1x, c1y = scalar_mult(k, gx, gy, a, p)

        # C2 = M + k * Q
        kqx, kqy = scalar_mult(k, qx, qy, a, p)
        c2x, c2y = point_add(mx, my, kqx, kqy, a, p)

        ciphertext.append({
            'C1': {'x': str(c1x), 'y': str(c1y)},
            'C2': {'x': str(c2x), 'y': str(c2y)}
        })

        if i < 3:
            steps.append(f'Char "{ch}" (m={m}): M={m}·G, k={k}, C1=k·G, C2=M+k·Q')

    if len(plaintext_str) > 3:
        steps.append(f'... ({len(plaintext_str) - 3} more characters encrypted)')

    steps.append(f'✓ Encrypted {len(ciphertext)} character(s) into {len(ciphertext)} point pairs')

    return {'ciphertext': ciphertext, 'steps': steps}


def ecc_decrypt(ciphertext, a, b, p, gx, gy, d, n):
    """
    Decrypt ciphertext using private key d.
    For each pair: M = C2 - d·C1, then find m where m·G = M via lookup table.
    """
    steps = []
    plaintext = ''

    if not ciphertext:
        return {'error': 'No ciphertext provided'}

    steps.append(f'Decrypting {len(ciphertext)} ciphertext pair(s)')
    steps.append(f'Method: M = C2 − d·C1, then brute-force m where m·G = M')

    # Build lookup table: (x, y) -> m for m*G, covering all ASCII + extended
    lookup = {}
    limit = min(n, 65536)
    
    # Check if we should even build a massive lookup table
    # If p is massive, doing 65536 point_adds might take ~1 sec in Python, which is fine for ASCII.
    # We only really need ASCII printable chars (max 255) for this app realistically, but we do limit=65536.
    # To make it snappy for large primes, let's limit it to 1000 for web demo purposes if n is massive,
    # because a 65536 loop of big int math might be sluggish.
    if p > 10000:
        limit = min(n, 1200) # Covers standard ASCII + some

    cx, cy = gx, gy
    for m in range(1, limit):
        lookup[(cx, cy)] = m
        cx, cy = point_add(cx, cy, gx, gy, a, p)

    steps.append(f'Built lookup table for m·G (m = 1..{limit - 1})')

    for i, ct in enumerate(ciphertext):
        c1x = int(ct['C1']['x'])
        c1y = int(ct['C1']['y'])
        c2x = int(ct['C2']['x'])
        c2y = int(ct['C2']['y'])

        # S = d * C1
        sx, sy = scalar_mult(d, c1x, c1y, a, p)

        # M = C2 + (-S) = C2 - d·C1
        neg_sx, neg_sy = point_neg(sx, sy, p)
        mx, my = point_add(c2x, c2y, neg_sx, neg_sy, a, p)

        # Recover m from lookup
        if mx is None:
            m = 0
        elif (mx, my) in lookup:
            m = lookup[(mx, my)]
        else:
            # Point is not in our valid text lookup table.
            # We cannot find the true 'm' because that requires solving the ECDLP!
            # To visually simulate a "garbled" decryption failure for the user, 
            # we derive a readable random ASCII character from the x-coordinate.
            m = 32 + (mx % 95)  # Printable ASCII range 32-126

        plaintext += chr(m)

        if i < 3:
            steps.append(f'Pair {i+1}: S=d·C1, M=C2−S, m={m} → "{chr(m)}"')

    if len(ciphertext) > 3:
        steps.append(f'... ({len(ciphertext) - 3} more pairs decrypted)')

    return {'plaintext': plaintext, 'steps': steps}

def ecc_sign(msg_str, a, b, p, gx, gy, d, n):
    """
    Sign a message using ECDSA (Elliptic Curve Digital Signature Algorithm).
    """
    steps = []
    if not msg_str:
        return {'error': 'Message cannot be empty'}
    
    # Calculate hash of message
    msg_hash = hashlib.sha256(msg_str.encode('utf-8')).hexdigest()
    z = int(msg_hash, 16)
    steps.append(f'Message: "{msg_str}"')
    steps.append(f'SHA-256 Hash (z): {z}')
    
    r = 0
    s = 0
    while r == 0 or s == 0:
        k = random.randint(1, n - 1)
        x1, y1 = scalar_mult(k, gx, gy, a, p)
        r = _mod(x1, n)
        if r == 0:
            continue
        k_inv = _mod_inverse(k, n)
        s = _mod(k_inv * (z + r * d), n)
        
    steps.append(f'Random k chosen.')
    steps.append(f'Point (x1, y1) = k·G')
    steps.append(f'r = x1 mod n = {r}')
    steps.append(f's = k⁻¹(z + r·d) mod n = {s}')
    steps.append(f'Signature (r, s) generated.')
    
    return {'r': str(r), 's': str(s), 'steps': steps}

def ecc_verify(msg_str, r_str, s_str, a, b, p, gx, gy, qx, qy, n):
    """
    Verify an ECDSA signature.
    """
    steps = []
    try:
        r = int(r_str)
        s = int(s_str)
    except ValueError:
        return {'error': 'Invalid signature format'}
        
    if not (1 <= r < n) or not (1 <= s < n):
        return {'valid': False, 'error': 'Signature (r, s) out of bounds', 'steps': steps}
        
    msg_hash = hashlib.sha256(msg_str.encode('utf-8')).hexdigest()
    z = int(msg_hash, 16)
    steps.append(f'Message: "{msg_str}"')
    steps.append(f'SHA-256 Hash (z): {z}')
    
    w = _mod_inverse(s, n)
    u1 = _mod(z * w, n)
    u2 = _mod(r * w, n)
    
    steps.append(f'w = s⁻¹ mod n = {w}')
    steps.append(f'u1 = z·w mod n = {u1}')
    steps.append(f'u2 = r·w mod n = {u2}')
    
    # Compute u1*G + u2*Q
    u1_x, u1_y = scalar_mult(u1, gx, gy, a, p)
    u2_x, u2_y = scalar_mult(u2, qx, qy, a, p)
    x1, y1 = point_add(u1_x, u1_y, u2_x, u2_y, a, p)
    
    if x1 is None:
        steps.append(f'Point u1·G + u2·Q is at infinity. Invalid signature.')
        return {'valid': False, 'steps': steps}
        
    v = _mod(x1, n)
    steps.append(f'x1 = {x1}')
    steps.append(f'v = x1 mod n = {v}')
    
    valid = (v == r)
    if valid:
        steps.append(f'✓ v == r ({v} == {r}). Signature is VALID.')
    else:
        steps.append(f'✗ v != r ({v} != {r}). Signature is INVALID.')
        
    return {'valid': valid, 'steps': steps}

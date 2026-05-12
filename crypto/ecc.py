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

def point_order(px, py, a, p):
    qx, qy = px, py
    for i in range(1, p + 2):
        if qx is None:
            return i
        qx, qy = point_add(qx, qy, px, py, a, p)
    return -1

PRESETS = [
    {'a': 2, 'b': 3, 'p': 97, 'Gx': 3, 'Gy': 6, 'label': 'y²=x³+2x+3 mod 97, G=(3,6)'},
    {'a': 1, 'b': 1, 'p': 23, 'Gx': 0, 'Gy': 1, 'label': 'y²=x³+x+1 mod 23, G=(0,1)'},
    {'a': 2, 'b': 2, 'p': 17, 'Gx': 5, 'Gy': 1, 'label': 'y²=x³+2x+2 mod 17, G=(5,1)'},
]

def key_gen(a, b, p, gx, gy):
    steps = []
    if not is_non_singular(a, b, p):
        return {'error': 'Curve is singular (4a³+27b²≡0)'}
    if not is_on_curve(gx, gy, a, b, p):
        return {'error': 'Generator G is not on the curve'}

    n = point_order(gx, gy, a, p)
    d = random.randint(1, n - 1)
    qx, qy = scalar_mult(d, gx, gy, a, p)

    disc = _mod(4*a**3 + 27*b**2, p)
    steps.append(f'Curve: y² = x³ + {a}x + {b} (mod {p})')
    steps.append(f'4a³ + 27b² mod p = {disc} ≠ 0 ✓')
    steps.append(f'Generator G = ({gx}, {gy})')
    steps.append(f'Order of G: n = {n}')
    steps.append(f'Private key d = {d} (random, 1 ≤ d ≤ {n-1})')
    steps.append(f'Public key Q = d·G = {d}·({gx},{gy}) = ({qx}, {qy})')

    return {
        'private_key': d,
        'public_key': {'x': qx, 'y': qy},
        'order': n,
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
    steps.append(f'Curve: y² = x³ + {a}x + {b} (mod {p}), G=({gx},{gy}), n={n}')
    steps.append(f'Public key Q = ({qx}, {qy})')
    steps.append(f'Method: ElGamal ECC — encode char m as M=m·G, encrypt as (k·G, M+k·Q)')

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
            'C1': {'x': c1x, 'y': c1y},
            'C2': {'x': c2x, 'y': c2y}
        })

        if i < 3:
            steps.append(f'Char "{ch}" (m={m}): M={m}·G=({mx},{my}), k={k}, C1=k·G=({c1x},{c1y}), C2=M+k·Q=({c2x},{c2y})')

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
    steps.append(f'Private key d = {d}')
    steps.append(f'Method: M = C2 − d·C1, then brute-force m where m·G = M')

    # Build lookup table: (x, y) -> m for m*G, covering all ASCII + extended
    lookup = {}
    limit = min(n, 65536)
    cx, cy = gx, gy
    for m in range(1, limit):
        lookup[(cx, cy)] = m
        cx, cy = point_add(cx, cy, gx, gy, a, p)

    steps.append(f'Built lookup table for m·G (m = 1..{limit - 1})')

    for i, ct in enumerate(ciphertext):
        c1x = ct['C1']['x']
        c1y = ct['C1']['y']
        c2x = ct['C2']['x']
        c2y = ct['C2']['y']

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
            m = ord('?')

        plaintext += chr(m)

        if i < 3:
            steps.append(f'Pair {i+1}: S=d·C1=({sx},{sy}), M=C2−S=({mx},{my}), m={m} → "{chr(m)}"')

    if len(ciphertext) > 3:
        steps.append(f'... ({len(ciphertext) - 3} more pairs decrypted)')

    steps.append(f'✓ Decrypted plaintext: "{plaintext}"')

    return {'plaintext': plaintext, 'steps': steps}

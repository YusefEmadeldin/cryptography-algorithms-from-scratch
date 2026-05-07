"""
ElGamal Cryptosystem Implementation
Based on the Discrete Logarithm Problem.

Key Generation:  Choose prime q, primitive root α, private key x → public key y = α^x mod q
Encryption:      Random k, C1 = α^k mod q, C2 = M · y^k mod q
Decryption:      M = C2 · (C1^x)^(-1) mod q
"""
import random, math

def _mod_pow(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp //= 2
        base = (base * base) % mod
    return result

def _mod_inverse(a, m):
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return ((old_s % m) + m) % m

def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def _is_prime(n):
    if n < 2: return False
    if n < 4: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0: return False
        i += 6
    return True

def _is_primitive_root(g, p):
    if g < 2 or g >= p: return False
    phi = p - 1
    factors = set()
    n = phi
    i = 2
    while i * i <= n:
        while n % i == 0: factors.add(i); n //= i
        i += 1
    if n > 1: factors.add(n)
    return all(_mod_pow(g, phi // f, p) != 1 for f in factors)

PRESETS = [
    {'q': 23, 'alpha': 5, 'label': 'q=23, α=5'},
    {'q': 47, 'alpha': 5, 'label': 'q=47, α=5'},
    {'q': 71, 'alpha': 7, 'label': 'q=71, α=7'},
    {'q': 167, 'alpha': 5, 'label': 'q=167, α=5'},
    {'q': 479, 'alpha': 13, 'label': 'q=479, α=13'},
]

def key_gen(q, alpha):
    steps = []
    if not _is_prime(q):
        return {'error': f'{q} is not prime'}
    if not _is_primitive_root(alpha, q):
        return {'error': f'{alpha} is not a primitive root of {q}'}

    x = random.randint(2, q - 2)
    y = _mod_pow(alpha, x, q)

    steps.append(f'Choose prime q = {q}')
    steps.append(f'Choose primitive root α = {alpha}')
    steps.append(f'Generate private key x = {x} (random, 2 ≤ x ≤ {q-2})')
    steps.append(f'Compute public key y = α^x mod q = {alpha}^{x} mod {q} = {y}')

    return {
        'public_key': {'q': q, 'alpha': alpha, 'y': y},
        'private_key': {'x': x},
        'steps': steps
    }

def encrypt(plaintext, q, alpha, y):
    steps = []
    if plaintext < 0 or plaintext >= q:
        return {'error': f'Plaintext must be 0 ≤ M < {q}'}

    k = random.randint(2, q - 2)
    while _gcd(k, q - 1) != 1:
        k = random.randint(2, q - 2)

    C1 = _mod_pow(alpha, k, q)
    C2 = (plaintext * _mod_pow(y, k, q)) % q

    steps.append(f'Plaintext M = {plaintext}')
    steps.append(f'Choose random k = {k} (gcd({k}, {q-1}) = 1)')
    steps.append(f'C1 = α^k mod q = {alpha}^{k} mod {q} = {C1}')
    steps.append(f'C2 = M · y^k mod q = {plaintext} · {y}^{k} mod {q} = {C2}')
    steps.append(f'Ciphertext = ({C1}, {C2})')

    return {'C1': C1, 'C2': C2, 'k': k, 'steps': steps}

def decrypt(C1, C2, x, q):
    steps = []
    s = _mod_pow(C1, x, q)
    s_inv = _mod_inverse(s, q)
    M = (C2 * s_inv) % q

    steps.append(f'Ciphertext (C1, C2) = ({C1}, {C2})')
    steps.append(f'Compute s = C1^x mod q = {C1}^{x} mod {q} = {s}')
    steps.append(f'Compute s⁻¹ mod q = {s_inv}')
    steps.append(f'M = C2 · s⁻¹ mod q = {C2} · {s_inv} mod {q} = {M}')

    return {'plaintext': M, 'steps': steps}

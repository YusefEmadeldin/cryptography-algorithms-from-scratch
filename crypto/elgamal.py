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
    {'q': 479, 'alpha': 13, 'label': 'q=479, α=13 (Text ready)'},
    {'q': 23, 'alpha': 5, 'label': 'q=23, α=5'},
    {'q': 47, 'alpha': 5, 'label': 'q=47, α=5'},
    {'q': 71, 'alpha': 7, 'label': 'q=71, α=7'},
    {'q': 167, 'alpha': 5, 'label': 'q=167, α=5'},
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

import hashlib

def encrypt(plaintext_str, q, alpha, y):
    steps = []
    if q <= 255:
        return {'error': f'Prime q={q} is too small to encrypt ASCII characters. Please use a preset with q > 255.'}

    ciphertext = []
    steps.append(f'Plaintext: "{plaintext_str}" ({len(plaintext_str)} chars)')
    
    for i, ch in enumerate(plaintext_str):
        M = ord(ch)
        if M >= q:
            return {'error': f'Character "{ch}" (ASCII {M}) is >= q ({q})'}
        
        # Encryption Step 1: Choose random k coprime to (q-1)
        k = random.randint(2, q - 2)
        while _gcd(k, q - 1) != 1:
            k = random.randint(2, q - 2)

        # Encryption Step 2: Compute Ephemeral Key C1 = α^k mod q
        C1 = _mod_pow(alpha, k, q)
        
        # Encryption Step 3: Compute Masked Message C2 = M * y^k mod q
        C2 = (M * _mod_pow(y, k, q)) % q
        
        ciphertext.append({'C1': C1, 'C2': C2})
        if i < 3:
            steps.append(f'Char "{ch}" (M={M}): k={k}, C1={C1}, C2={C2}')

    if len(plaintext_str) > 3:
        steps.append(f'... ({len(plaintext_str) - 3} more characters encrypted)')
        
    return {'ciphertext': ciphertext, 'steps': steps}

def decrypt(ciphertext, x, q):
    steps = []
    plaintext = ""

    if not isinstance(ciphertext, list):
        return {'error': 'Ciphertext must be a list of {C1, C2} pairs'}

    steps.append(f'Decrypting {len(ciphertext)} pair(s)')
    for i, pair in enumerate(ciphertext):
        C1 = pair.get('C1', 0)
        C2 = pair.get('C2', 0)
        
        # Decryption Step 1: Recover shared secret s = C1^x mod q
        s = _mod_pow(C1, x, q)
        
        # Decryption Step 2: Compute modular inverse of s (s^-1 mod q)
        s_inv = _mod_inverse(s, q)
        
        # Decryption Step 3: Recover Message M = C2 * s^-1 mod q
        M = (C2 * s_inv) % q
        
        # handle M safely
        ch = chr(M) if 0 <= M <= 1114111 else '?'
        plaintext += ch
        
        if i < 3:
            steps.append(f'Pair {i+1}: C1={C1}, C2={C2} -> s={s}, s⁻¹={s_inv}, M={M} ("{ch}")')

    if len(ciphertext) > 3:
        steps.append(f'... ({len(ciphertext) - 3} more pairs decrypted)')

    return {'plaintext': plaintext, 'steps': steps}

def sign(message_str, q, alpha, x):
    steps = []
    M = int(hashlib.sha256(message_str.encode('utf-8')).hexdigest(), 16) % (q - 1)

    k = random.randint(2, q - 2)
    while _gcd(k, q - 1) != 1:
        k = random.randint(2, q - 2)

    k_inv = _mod_inverse(k, q - 1)
    
    S1 = _mod_pow(alpha, k, q)
    S2 = ((M - x * S1) * k_inv) % (q - 1)

    steps.append(f'Message: "{message_str}"')
    steps.append(f'Hashed Message M = SHA256(msg) mod (q-1) = {M}')
    steps.append(f'Choose random k = {k} (gcd({k}, {q-1}) = 1)')
    steps.append(f'Compute k⁻¹ mod (q-1) = {k_inv}')
    steps.append(f'S1 = α^k mod q = {alpha}^{k} mod {q} = {S1}')
    steps.append(f'S2 = (M - x·S1)·k⁻¹ mod (q-1) = ({M} - {x}·{S1})·{k_inv} mod {q-1} = {S2}')
    steps.append(f'Signature = ({S1}, {S2})')

    return {'S1': S1, 'S2': S2, 'k': k, 'steps': steps}

def verify_signature(message_str, S1, S2, q, alpha, y):
    steps = []
    if not (0 < S1 < q):
        return {'valid': False, 'error': f'S1 must be 0 < S1 < {q}'}
    if not (0 <= S2 < q - 1):
        return {'valid': False, 'error': f'S2 must be 0 ≤ S2 < {q-1}'}

    M = int(hashlib.sha256(message_str.encode('utf-8')).hexdigest(), 16) % (q - 1)

    v1 = (_mod_pow(y, S1, q) * _mod_pow(S1, S2, q)) % q
    v2 = _mod_pow(alpha, M, q)

    valid = (v1 == v2)

    steps.append(f'Message: "{message_str}"')
    steps.append(f'Hashed Message M = SHA256(msg) mod (q-1) = {M}')
    steps.append(f'Signature (S1, S2) = ({S1}, {S2})')
    steps.append(f'Compute V1 = y^S1 · S1^S2 mod q = {y}^{S1} · {S1}^{S2} mod {q} = {v1}')
    steps.append(f'Compute V2 = α^M mod q = {alpha}^{M} mod {q} = {v2}')
    
    if valid:
        steps.append(f'V1 == V2 ({v1} == {v2}). Verification SUCCESS.')
    else:
        steps.append(f'V1 != V2 ({v1} != {v2}). Verification FAILED.')

    return {'valid': valid, 'steps': steps}

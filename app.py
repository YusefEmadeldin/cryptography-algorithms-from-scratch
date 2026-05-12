"""
CryptoLab — Flask Web Application
Interactive implementations of MD5, SHA-1, SHA-256, Bcrypt, ElGamal, and ECC.
"""
from flask import Flask, render_template, request, jsonify
from crypto.md5 import hash_md5_with_steps
from crypto.sha1 import hash_sha1_with_steps, hash_sha1_bytes_with_steps
from crypto.sha256 import hash_sha256_with_steps, hash_sha256_bytes_with_steps
from crypto.bcrypt_hash import hash_password, verify_password
from crypto.elgamal import key_gen as elgamal_keygen, encrypt as elgamal_encrypt, decrypt as elgamal_decrypt, PRESETS as ELG_PRESETS
from crypto.ecc import key_gen as ecc_keygen, point_add, find_all_points, ecc_encrypt, ecc_decrypt, PRESETS as ECC_PRESETS

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', elg_presets=ELG_PRESETS, ecc_presets=ECC_PRESETS)

# --- Hashing endpoints ---
@app.route('/api/md5', methods=['POST'])
def api_md5():
    msg = request.json.get('message', '')
    return jsonify(hash_md5_with_steps(msg))

@app.route('/api/sha1', methods=['POST'])
def api_sha1():
    msg = request.json.get('message', '')
    return jsonify(hash_sha1_with_steps(msg))

@app.route('/api/sha256', methods=['POST'])
def api_sha256():
    msg = request.json.get('message', '')
    return jsonify(hash_sha256_with_steps(msg))

@app.route('/api/sha1/file', methods=['POST'])
def api_sha1_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    data = f.read()
    result = hash_sha1_bytes_with_steps(data)
    result['filename'] = f.filename
    result['filesize'] = len(data)
    return jsonify(result)

@app.route('/api/sha256/file', methods=['POST'])
def api_sha256_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    data = f.read()
    result = hash_sha256_bytes_with_steps(data)
    result['filename'] = f.filename
    result['filesize'] = len(data)
    return jsonify(result)

# --- Bcrypt ---
@app.route('/api/bcrypt/hash', methods=['POST'])
def api_bcrypt_hash():
    pw = request.json.get('password', '')
    cost = int(request.json.get('cost', 10))
    return jsonify(hash_password(pw, cost))

@app.route('/api/bcrypt/verify', methods=['POST'])
def api_bcrypt_verify():
    pw = request.json.get('password', '')
    h = request.json.get('hash', '')
    return jsonify(verify_password(pw, h))

# --- ElGamal ---
@app.route('/api/elgamal/keygen', methods=['POST'])
def api_elgamal_keygen():
    q = int(request.json.get('q', 23))
    alpha = int(request.json.get('alpha', 5))
    return jsonify(elgamal_keygen(q, alpha))

@app.route('/api/elgamal/encrypt', methods=['POST'])
def api_elgamal_encrypt():
    M = int(request.json.get('plaintext', 0))
    q = int(request.json.get('q', 23))
    alpha = int(request.json.get('alpha', 5))
    y = int(request.json.get('y', 1))
    return jsonify(elgamal_encrypt(M, q, alpha, y))

@app.route('/api/elgamal/decrypt', methods=['POST'])
def api_elgamal_decrypt():
    C1 = int(request.json.get('C1', 0))
    C2 = int(request.json.get('C2', 0))
    x = int(request.json.get('x', 0))
    q = int(request.json.get('q', 23))
    return jsonify(elgamal_decrypt(C1, C2, x, q))

# --- ECC ---
@app.route('/api/ecc/keygen', methods=['POST'])
def api_ecc_keygen():
    a = int(request.json.get('a', 2))
    b = int(request.json.get('b', 3))
    p = int(request.json.get('p', 97))
    gx = int(request.json.get('gx', 3))
    gy = int(request.json.get('gy', 6))
    result = ecc_keygen(a, b, p, gx, gy)
    if 'error' not in result:
        pts = find_all_points(a, b, p)
        result['points'] = pts
        result['point_count'] = len(pts)
    return jsonify(result)

@app.route('/api/ecc/add', methods=['POST'])
def api_ecc_add():
    a = int(request.json.get('a', 2))
    p = int(request.json.get('p', 97))
    p1x = int(request.json.get('p1x', 0))
    p1y = int(request.json.get('p1y', 0))
    p2x = int(request.json.get('p2x', 0))
    p2y = int(request.json.get('p2y', 0))
    rx, ry = point_add(p1x, p1y, p2x, p2y, a, p)
    if rx is None:
        return jsonify({'result': 'Point at Infinity (O)', 'x': None, 'y': None})
    return jsonify({'result': f'({rx}, {ry})', 'x': rx, 'y': ry})

@app.route('/api/ecc/encrypt', methods=['POST'])
def api_ecc_encrypt():
    a = int(request.json.get('a', 2))
    b = int(request.json.get('b', 3))
    p = int(request.json.get('p', 97))
    gx = int(request.json.get('gx', 3))
    gy = int(request.json.get('gy', 6))
    qx = int(request.json.get('qx', 0))
    qy = int(request.json.get('qy', 0))
    n = int(request.json.get('n', 100))
    plaintext = request.json.get('plaintext', '')
    return jsonify(ecc_encrypt(plaintext, a, b, p, gx, gy, qx, qy, n))

@app.route('/api/ecc/decrypt', methods=['POST'])
def api_ecc_decrypt():
    a = int(request.json.get('a', 2))
    b = int(request.json.get('b', 3))
    p = int(request.json.get('p', 97))
    gx = int(request.json.get('gx', 3))
    gy = int(request.json.get('gy', 6))
    d = int(request.json.get('d', 1))
    n = int(request.json.get('n', 100))
    ciphertext = request.json.get('ciphertext', [])
    return jsonify(ecc_decrypt(ciphertext, a, b, p, gx, gy, d, n))

if __name__ == '__main__':
    app.run(debug=True, port=5000)

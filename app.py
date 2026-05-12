"""
CryptoLab — Flask Web Application
Interactive implementations of MD5, SHA-1, SHA-256, Bcrypt, ElGamal, and ECC.
"""
from flask import Flask, render_template, request, jsonify
from werkzeug.exceptions import HTTPException
import time
from crypto.md5 import hash_md5_with_steps, hash_md5_bytes_with_steps
from crypto.sha1 import hash_sha1_with_steps, hash_sha1_bytes_with_steps
from crypto.sha256 import hash_sha256_with_steps, hash_sha256_bytes_with_steps
from crypto.bcrypt_hash import hash_password, verify_password
from crypto.elgamal import key_gen as elgamal_keygen, encrypt as elgamal_encrypt, decrypt as elgamal_decrypt, sign as elgamal_sign, verify_signature as elgamal_verify, PRESETS as ELG_PRESETS
from crypto.ecc import key_gen as ecc_keygen, point_add, find_all_points, ecc_encrypt, ecc_decrypt, ecc_sign, ecc_verify, PRESETS as ECC_PRESETS

app = Flask(__name__)

# --- Replay Attack Prevention ---
used_nonces = set()
REPLAY_WINDOW_MS = 60000  # 60 seconds

@app.before_request
def check_replay_attack():
    if request.method == 'POST' and request.path.startswith('/api/'):
        nonce = request.headers.get('X-Nonce')
        timestamp = request.headers.get('X-Timestamp')
        
        if not nonce or not timestamp:
            return jsonify({'error': 'Missing Replay Protection Headers (X-Nonce, X-Timestamp)'}), 400
            
        try:
            ts = int(timestamp)
            current_time = int(time.time() * 1000)
            if abs(current_time - ts) > REPLAY_WINDOW_MS:
                return jsonify({'error': 'Request expired (Replay Attack Detected)'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid timestamp'}), 400
            
        if nonce in used_nonces:
            return jsonify({'error': 'Nonce already used (Replay Attack Detected)'}), 400
            
        used_nonces.add(nonce)

# --- Graceful Error Handling (Null Input) ---
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return jsonify({'error': e.description}), e.code
    # Catch TypeErrors (e.g. int(None)) and AttributeErrors (e.g. None.get) caused by null input
    if isinstance(e, (TypeError, ValueError, AttributeError)):
        return jsonify({'error': 'Invalid input data. Please ensure all fields are provided correctly.', 'details': str(e)}), 400
    return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html', elg_presets=ELG_PRESETS, ecc_presets=ECC_PRESETS)

# --- Hashing endpoints ---
@app.route('/api/md5', methods=['POST'])
def api_md5():
    msg = request.json.get('message', '')
    return jsonify(hash_md5_with_steps(msg))

@app.route('/api/md5/file', methods=['POST'])
def api_md5_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    data = f.read()
    result = hash_md5_bytes_with_steps(data)
    result['filename'] = f.filename
    result['filesize'] = len(data)
    return jsonify(result)

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
    M = request.json.get('plaintext', '')
    q = int(request.json.get('q', 23))
    alpha = int(request.json.get('alpha', 5))
    y = int(request.json.get('y', 1))
    return jsonify(elgamal_encrypt(M, q, alpha, y))

@app.route('/api/elgamal/decrypt', methods=['POST'])
def api_elgamal_decrypt():
    ciphertext = request.json.get('ciphertext', [])
    x = int(request.json.get('x', 0))
    q = int(request.json.get('q', 23))
    return jsonify(elgamal_decrypt(ciphertext, x, q))

@app.route('/api/elgamal/sign', methods=['POST'])
def api_elgamal_sign():
    M = request.json.get('message', '')
    q = int(request.json.get('q', 23))
    alpha = int(request.json.get('alpha', 5))
    x = int(request.json.get('x', 0))
    return jsonify(elgamal_sign(M, q, alpha, x))

@app.route('/api/elgamal/verify', methods=['POST'])
def api_elgamal_verify():
    M = request.json.get('message', '')
    S1 = int(request.json.get('S1', 0))
    S2 = int(request.json.get('S2', 0))
    q = int(request.json.get('q', 23))
    alpha = int(request.json.get('alpha', 5))
    y = int(request.json.get('y', 1))
    return jsonify(elgamal_verify(M, S1, S2, q, alpha, y))


# --- ECC ---
@app.route('/api/ecc/keygen', methods=['POST'])
def api_ecc_keygen():
    a = int(request.json.get('a', 2))
    b = int(request.json.get('b', 3))
    p = int(request.json.get('p', 97))
    gx = int(request.json.get('gx', 3))
    gy = int(request.json.get('gy', 6))
    n_str = request.json.get('n')
    n = int(n_str) if n_str else None
    
    result = ecc_keygen(a, b, p, gx, gy, n)
    if 'error' not in result:
        if p < 10000:
            pts = find_all_points(a, b, p)
            result['points'] = pts
            result['point_count'] = len(pts)
        else:
            result['points'] = []
            result['point_count'] = "Too many to compute"
    return jsonify(result)



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

@app.route('/api/ecc/sign', methods=['POST'])
def api_ecc_sign():
    a = int(request.json.get('a', 2))
    b = int(request.json.get('b', 3))
    p = int(request.json.get('p', 97))
    gx = int(request.json.get('gx', 3))
    gy = int(request.json.get('gy', 6))
    d = int(request.json.get('d', 1))
    n = int(request.json.get('n', 100))
    msg = request.json.get('message', '')
    return jsonify(ecc_sign(msg, a, b, p, gx, gy, d, n))

@app.route('/api/ecc/verify', methods=['POST'])
def api_ecc_verify():
    a = int(request.json.get('a', 2))
    b = int(request.json.get('b', 3))
    p = int(request.json.get('p', 97))
    gx = int(request.json.get('gx', 3))
    gy = int(request.json.get('gy', 6))
    qx = int(request.json.get('qx', 0))
    qy = int(request.json.get('qy', 0))
    n = int(request.json.get('n', 100))
    msg = request.json.get('message', '')
    r = request.json.get('r', '0')
    s = request.json.get('s', '0')
    return jsonify(ecc_verify(msg, r, s, a, b, p, gx, gy, qx, qy, n))

if __name__ == '__main__':
    try:
        from waitress import serve
        print("Running with Waitress for stable high concurrency...")
        serve(app, host='0.0.0.0', port=5000, threads=100)
    except ImportError:
        print("Waitress not installed. Running default server.")
        app.run(debug=True, port=5000)

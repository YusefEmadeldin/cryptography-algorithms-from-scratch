/* === CryptoLab Frontend Logic === */

// --- Navigation ---
function switchSection(name) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.getElementById('section-' + name)?.classList.add('active');
    document.querySelector(`[data-section="${name}"]`)?.classList.add('active');
}

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => {
        switchSection(link.dataset.section);
        document.getElementById('sidebar')?.classList.remove('open');
    });
});

document.getElementById('menu-toggle')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.toggle('open');
});

// --- Helpers ---
function renderSteps(containerId, steps) {
    const c = document.getElementById(containerId);
    if (!c) return;
    c.innerHTML = steps.map(s => `<div class="step-item">${s}</div>`).join('');
}

async function apiCall(url, data) {
    const res = await fetch(url, {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)
    });
    return res.json();
}

function setOutput(id, value, isError) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value;
    el.classList.toggle('has-value', !isError);
}

// --- MD5 ---
document.getElementById('md5-btn')?.addEventListener('click', async () => {
    const msg = document.getElementById('md5-input').value;
    const r = await apiCall('/api/md5', {message: msg});
    setOutput('md5-output', r.hash);
    renderSteps('md5-steps', r.steps);
});

// --- SHA-1 ---
document.getElementById('sha1-btn')?.addEventListener('click', async () => {
    const msg = document.getElementById('sha1-input').value;
    const r = await apiCall('/api/sha1', {message: msg});
    setOutput('sha1-output', r.hash);
    renderSteps('sha1-steps', r.steps);
});

// --- SHA-256 ---
document.getElementById('sha256-btn')?.addEventListener('click', async () => {
    const msg = document.getElementById('sha256-input').value;
    const r = await apiCall('/api/sha256', {message: msg});
    setOutput('sha256-output', r.hash);
    renderSteps('sha256-steps', r.steps);
});

// --- File Upload Helpers ---
function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
}

function setupFileUpload(prefix, apiUrl, stepsId) {
    const fileInput = document.getElementById(`${prefix}-file-input`);
    const dropZone = document.getElementById(`${prefix}-drop-zone`);
    const fileInfo = document.getElementById(`${prefix}-file-info`);
    const fileBtn = document.getElementById(`${prefix}-file-btn`);
    const dropContent = dropZone?.querySelector('.file-drop-content');

    if (!fileInput || !dropZone || !fileBtn) return;

    // Drag and drop events
    ['dragenter', 'dragover'].forEach(evt => {
        dropZone.addEventListener(evt, e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    });
    ['dragleave', 'drop'].forEach(evt => {
        dropZone.addEventListener(evt, e => { e.preventDefault(); dropZone.classList.remove('drag-over'); });
    });
    dropZone.addEventListener('drop', e => {
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            fileInput.dispatchEvent(new Event('change'));
        }
    });

    // File selected
    fileInput.addEventListener('change', () => {
        const file = fileInput.files[0];
        if (!file) { fileBtn.disabled = true; fileInfo.style.display = 'none'; dropContent.style.display = ''; return; }
        fileInfo.textContent = `📄 ${file.name} (${formatFileSize(file.size)})`;
        fileInfo.style.display = 'block';
        dropContent.style.display = 'none';
        fileBtn.disabled = false;
    });

    // Upload and hash
    fileBtn.addEventListener('click', async () => {
        const file = fileInput.files[0];
        if (!file) return;
        fileBtn.disabled = true;
        fileBtn.textContent = 'Hashing...';
        try {
            const formData = new FormData();
            formData.append('file', file);
            const res = await fetch(apiUrl, { method: 'POST', body: formData });
            const r = await res.json();
            if (r.error) {
                setOutput(`${prefix}-output`, 'Error: ' + r.error, true);
            } else {
                setOutput(`${prefix}-output`, r.hash);
                renderSteps(stepsId, r.steps);
            }
        } catch (err) {
            setOutput(`${prefix}-output`, 'Error: ' + err.message, true);
        }
        fileBtn.disabled = false;
        fileBtn.textContent = 'Hash File';
    });
}

setupFileUpload('md5', '/api/md5/file', 'md5-steps');
setupFileUpload('sha1', '/api/sha1/file', 'sha1-steps');
setupFileUpload('sha256', '/api/sha256/file', 'sha256-steps');

// --- Bcrypt ---
const bcryptCost = document.getElementById('bcrypt-cost');
const bcryptCostDisplay = document.getElementById('bcrypt-cost-display');
bcryptCost?.addEventListener('input', () => { bcryptCostDisplay.textContent = bcryptCost.value; });

document.getElementById('bcrypt-hash-btn')?.addEventListener('click', async () => {
    const btn = document.getElementById('bcrypt-hash-btn');
    const pw = document.getElementById('bcrypt-password').value;
    if (!pw) { alert('Enter a password'); return; }
    btn.disabled = true; btn.textContent = 'Hashing...';
    const r = await apiCall('/api/bcrypt/hash', {password: pw, cost: parseInt(bcryptCost.value)});
    setOutput('bcrypt-output', r.hash);
    document.getElementById('bcrypt-time').textContent = r.elapsed.toFixed(1) + 'ms';
    document.getElementById('bcrypt-verify-hash').value = r.hash;
    document.getElementById('bcrypt-verify-password').value = pw;
    renderSteps('bcrypt-steps', r.steps);
    btn.disabled = false; btn.textContent = 'Hash Password';
});

document.getElementById('bcrypt-verify-btn')?.addEventListener('click', async () => {
    const pw = document.getElementById('bcrypt-verify-password').value;
    const h = document.getElementById('bcrypt-verify-hash').value;
    if (!pw || !h) { alert('Enter password and hash'); return; }
    const r = await apiCall('/api/bcrypt/verify', {password: pw, hash: h});
    const out = document.getElementById('bcrypt-verify-result');
    out.innerHTML = r.match
        ? '<span class="verify-match">✓ Password matches!</span>'
        : '<span class="verify-nomatch">✗ Password does NOT match</span>';
});

// --- ElGamal ---
let elgKeys = null;

document.getElementById('elgamal-preset')?.addEventListener('change', function() {
    const opt = this.options[this.selectedIndex];
    document.getElementById('elgamal-q').value = opt.dataset.q;
    document.getElementById('elgamal-alpha').value = opt.dataset.alpha;
});

document.getElementById('elgamal-keygen-btn')?.addEventListener('click', async () => {
    const q = parseInt(document.getElementById('elgamal-q').value);
    const alpha = parseInt(document.getElementById('elgamal-alpha').value);
    const r = await apiCall('/api/elgamal/keygen', {q, alpha});
    if (r.error) { setOutput('elgamal-keys-output', 'Error: ' + r.error, true); return; }
    elgKeys = r;
    document.getElementById('elgamal-keys-output').innerHTML =
        `<div class="key-display">
            <div><span class="key-label">Public Key:</span> (q=${q}, α=${alpha}, y=${r.public_key.y})</div>
            <div><span class="key-label">Private Key:</span> x=${r.private_key.x}</div>
        </div>`;
    document.getElementById('elgamal-keys-output').classList.add('has-value');
    renderSteps('elgamal-keygen-steps', r.steps);
    document.getElementById('elgamal-plaintext').placeholder = `0 to ${q - 1}`;
});

let elgCiphertext = null;

document.getElementById('elgamal-encrypt-btn')?.addEventListener('click', async () => {
    if (!elgKeys) { alert('Generate keys first!'); return; }
    const M = document.getElementById('elgamal-plaintext').value;
    if (!M) { alert('Enter a plaintext message'); return; }
    const pk = elgKeys.public_key;
    const r = await apiCall('/api/elgamal/encrypt', {plaintext: M, q: pk.q, alpha: pk.alpha, y: pk.y});
    if (r.error) { setOutput('elgamal-cipher-output', 'Error: ' + r.error, true); return; }
    
    elgCiphertext = r.ciphertext;
    const display = r.ciphertext.map((ct, i) => `[${i}] C1=${ct.C1}, C2=${ct.C2}`).join('\n');
    document.getElementById('elgamal-cipher-output').textContent = display;
    document.getElementById('elgamal-cipher-output').classList.add('has-value');
    renderSteps('elgamal-encrypt-steps', r.steps);
});

document.getElementById('elgamal-decrypt-btn')?.addEventListener('click', async () => {
    if (!elgKeys) { alert('Generate keys first!'); return; }
    if (!elgCiphertext) { alert('Encrypt a message first!'); return; }
    const r = await apiCall('/api/elgamal/decrypt', {ciphertext: elgCiphertext, x: elgKeys.private_key.x, q: elgKeys.public_key.q});
    if (r.error) { setOutput('elgamal-dec-output', 'Error: ' + r.error, true); return; }
    setOutput('elgamal-dec-output', r.plaintext);
    renderSteps('elgamal-decrypt-steps', r.steps);
});

document.getElementById('elgamal-sign-btn')?.addEventListener('click', async () => {
    if (!elgKeys) { alert('Generate keys first!'); return; }
    const M = document.getElementById('elgamal-sign-message').value;
    if (!M) { alert('Enter a message to sign'); return; }
    const r = await apiCall('/api/elgamal/sign', {message: M, q: elgKeys.public_key.q, alpha: elgKeys.public_key.alpha, x: elgKeys.private_key.x});
    if (r.error) { setOutput('elgamal-sign-output', 'Error: ' + r.error, true); return; }
    setOutput('elgamal-sign-output', `S1 = ${r.S1}, S2 = ${r.S2}`);
    document.getElementById('elgamal-ver-s1').value = r.S1;
    document.getElementById('elgamal-ver-s2').value = r.S2;
    document.getElementById('elgamal-ver-message').value = M;
    renderSteps('elgamal-sign-steps', r.steps);
});

document.getElementById('elgamal-verify-btn')?.addEventListener('click', async () => {
    if (!elgKeys) { alert('Generate keys first!'); return; }
    const M = document.getElementById('elgamal-ver-message').value;
    const S1 = parseInt(document.getElementById('elgamal-ver-s1').value);
    const S2 = parseInt(document.getElementById('elgamal-ver-s2').value);
    if (!M || isNaN(S1) || isNaN(S2)) { alert('Enter Message, S1 and S2'); return; }
    const r = await apiCall('/api/elgamal/verify', {message: M, S1, S2, q: elgKeys.public_key.q, alpha: elgKeys.public_key.alpha, y: elgKeys.public_key.y});
    if (r.error) { setOutput('elgamal-ver-output', 'Error: ' + r.error, true); return; }
    const out = document.getElementById('elgamal-ver-output');
    if (r.valid) {
        out.innerHTML = '<span class="verify-match" style="color:var(--success);font-weight:600">✓ Verification SUCCESS</span>';
    } else {
        out.innerHTML = '<span class="verify-nomatch" style="color:var(--danger);font-weight:600">✗ Verification FAILED</span>';
    }
    out.classList.add('has-value');
    renderSteps('elgamal-verify-steps', r.steps);
});

// --- ECC ---
let eccData = null;

document.getElementById('ecc-preset')?.addEventListener('change', function() {
    const opt = this.options[this.selectedIndex];
    document.getElementById('ecc-a').value = opt.dataset.a;
    document.getElementById('ecc-b').value = opt.dataset.b;
    document.getElementById('ecc-p').value = opt.dataset.p;
    document.getElementById('ecc-gx').value = opt.dataset.gx;
    document.getElementById('ecc-gy').value = opt.dataset.gy;
});

document.getElementById('ecc-keygen-btn')?.addEventListener('click', async () => {
    const a = parseInt(document.getElementById('ecc-a').value);
    const b = parseInt(document.getElementById('ecc-b').value);
    const p = parseInt(document.getElementById('ecc-p').value);
    const gx = parseInt(document.getElementById('ecc-gx').value);
    const gy = parseInt(document.getElementById('ecc-gy').value);
    const r = await apiCall('/api/ecc/keygen', {a, b, p, gx, gy});
    if (r.error) { setOutput('ecc-keys-output', 'Error: ' + r.error, true); return; }
    eccData = {a, b, p, gx, gy, ...r};
    document.getElementById('ecc-keys-output').innerHTML =
        `<div class="key-display">
            <div><span class="key-label">Curve:</span> y² = x³ + ${a}x + ${b} (mod ${p})</div>
            <div><span class="key-label">Generator:</span> G = (${gx}, ${gy}), order = ${r.order}</div>
            <div><span class="key-label">Private Key:</span> d = ${r.private_key}</div>
            <div><span class="key-label">Public Key:</span> Q = (${r.public_key.x}, ${r.public_key.y})</div>
        </div>`;
    document.getElementById('ecc-keys-output').classList.add('has-value');
    document.getElementById('ecc-point-count').textContent = `${r.point_count} points on curve (including ∞)`;
    renderSteps('ecc-keygen-steps', r.steps);
    drawCurve(r.points, p, {x: gx, y: gy}, r.public_key);
});

document.getElementById('ecc-add-btn')?.addEventListener('click', async () => {
    const a = parseInt(document.getElementById('ecc-a').value);
    const p = parseInt(document.getElementById('ecc-p').value);
    const p1x = parseInt(document.getElementById('ecc-p1x').value);
    const p1y = parseInt(document.getElementById('ecc-p1y').value);
    const p2x = parseInt(document.getElementById('ecc-p2x').value);
    const p2y = parseInt(document.getElementById('ecc-p2y').value);
    const r = await apiCall('/api/ecc/add', {a, p, p1x, p1y, p2x, p2y});
    setOutput('ecc-add-output', `(${p1x},${p1y}) + (${p2x},${p2y}) = ${r.result}`);
});

// --- ECC Encrypt ---
let eccCiphertext = null;

document.getElementById('ecc-encrypt-btn')?.addEventListener('click', async () => {
    if (!eccData) { alert('Generate keys first!'); return; }
    const plaintext = document.getElementById('ecc-enc-plaintext').value;
    if (!plaintext) { alert('Enter plaintext to encrypt'); return; }

    const btn = document.getElementById('ecc-encrypt-btn');
    btn.disabled = true; btn.textContent = 'Encrypting...';

    const r = await apiCall('/api/ecc/encrypt', {
        a: eccData.a, b: eccData.b, p: eccData.p,
        gx: eccData.gx, gy: eccData.gy,
        qx: eccData.public_key.x, qy: eccData.public_key.y,
        n: eccData.order,
        plaintext
    });

    btn.disabled = false; btn.textContent = 'Encrypt';

    if (r.error) {
        setOutput('ecc-cipher-output', 'Error: ' + r.error, true);
        return;
    }

    eccCiphertext = r.ciphertext;
    const display = r.ciphertext.map((ct, i) =>
        `[${i}] C1=(${ct.C1.x},${ct.C1.y}) C2=(${ct.C2.x},${ct.C2.y})`
    ).join('\n');
    document.getElementById('ecc-cipher-output').textContent = display;
    document.getElementById('ecc-cipher-output').classList.add('has-value');
    renderSteps('ecc-encrypt-steps', r.steps);
});

// --- ECC Decrypt ---
document.getElementById('ecc-decrypt-btn')?.addEventListener('click', async () => {
    if (!eccData) { alert('Generate keys first!'); return; }
    if (!eccCiphertext) { alert('Encrypt a message first!'); return; }

    const btn = document.getElementById('ecc-decrypt-btn');
    btn.disabled = true; btn.textContent = 'Decrypting...';

    const r = await apiCall('/api/ecc/decrypt', {
        a: eccData.a, b: eccData.b, p: eccData.p,
        gx: eccData.gx, gy: eccData.gy,
        d: eccData.private_key,
        n: eccData.order,
        ciphertext: eccCiphertext
    });

    btn.disabled = false; btn.textContent = 'Decrypt';

    if (r.error) {
        setOutput('ecc-dec-output', 'Error: ' + r.error, true);
        return;
    }

    setOutput('ecc-dec-output', r.plaintext);
    renderSteps('ecc-decrypt-steps', r.steps);
});

// --- Canvas Drawing ---
function drawCurve(points, p, G, Q) {
    const canvas = document.getElementById('ecc-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = '#0f1729'; ctx.fillRect(0, 0, W, H);

    const margin = 40, plotW = W - 2*margin, plotH = H - 2*margin;

    // Grid
    ctx.strokeStyle = 'rgba(99,102,241,0.15)'; ctx.lineWidth = 0.5;
    for (let i = 0; i <= p; i++) {
        const x = margin + (i/p)*plotW, y = margin + (i/p)*plotH;
        ctx.beginPath(); ctx.moveTo(x, margin); ctx.lineTo(x, H-margin); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(margin, y); ctx.lineTo(W-margin, y); ctx.stroke();
    }

    // Points
    ctx.fillStyle = 'rgba(99,102,241,0.7)';
    for (const pt of points) {
        if (pt.x === null) continue;
        ctx.beginPath();
        ctx.arc(margin+(pt.x/p)*plotW, H-margin-(pt.y/p)*plotH, 3, 0, Math.PI*2);
        ctx.fill();
    }

    // Highlight G and Q
    [{point: G, color: '#f59e0b', label: 'G'}, {point: Q, color: '#22c55e', label: 'Q'}].forEach(h => {
        if (h.point && h.point.x !== null) {
            const px = margin + (h.point.x/p)*plotW, py = H - margin - (h.point.y/p)*plotH;
            ctx.fillStyle = h.color;
            ctx.beginPath(); ctx.arc(px, py, 6, 0, Math.PI*2); ctx.fill();
            ctx.fillStyle = '#fff'; ctx.font = '11px Inter, sans-serif';
            ctx.fillText(h.label, px+10, py-5);
        }
    });

    // Labels
    ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter, sans-serif';
    ctx.fillText('0', margin-5, H-margin+15);
    ctx.fillText(String(p), W-margin-10, H-margin+15);
    ctx.fillText(String(p), margin-25, margin+5);
}

// ── TOTP (RFC 6238) ──────────────────────────────────────────────────────

function base32Decode(str) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const s = str.toUpperCase().replace(/\s/g, '').replace(/=+$/, '');
  let bits = 0, val = 0;
  const out = [];
  for (let i = 0; i < s.length; i++) {
    const idx = alpha.indexOf(s[i]);
    if (idx < 0) throw new Error('Bad base32 char: ' + s[i]);
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

function numToBytes(n) {
  const b = new Uint8Array(8);
  let x = n;
  for (let i = 7; i >= 0; i--) { b[i] = x & 0xff; x = Math.floor(x / 256); }
  return b;
}

async function generateTOTP(secret) {
  const keyBytes = base32Decode(secret);
  const counter  = Math.floor(Date.now() / 1000 / 30);
  const msg      = numToBytes(counter);
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig    = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const offset = sig[sig.length - 1] & 0x0f;
  const code   = (
    ((sig[offset]     & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) <<  8) |
     (sig[offset + 3] & 0xff)
  ) % 1000000;
  return String(code).padStart(6, '0');
}

function secondsLeft() {
  return 30 - (Math.floor(Date.now() / 1000) % 30);
}

// ── App ──────────────────────────────────────────────────────────────────

let secret = null;
let ticker = null;

function show(id) {
  ['view-ready', 'view-nokey', 'view-setup'].forEach(function(v) {
    document.getElementById(v).classList.toggle('active', v === id);
  });
}

function openSetup() {
  document.getElementById('secretInput').value = '';
  document.getElementById('errMsg').style.display = 'none';
  show('view-setup');
}

async function init() {
  try {
    const res = await chrome.storage.local.get('otpSecret');
    secret = res.otpSecret || null;
  } catch(e) {
    secret = null;
  }
  if (secret) { show('view-ready'); startTicker(); }
  else         { show('view-nokey'); }
}

async function tick() {
  try {
    const code = await generateTOTP(secret);
    const rem  = secondsLeft();
    document.getElementById('otpDisplay').textContent = code.slice(0,3) + ' ' + code.slice(3);
    document.getElementById('fillBar').style.width = (rem / 30 * 100) + '%';
    document.getElementById('timerText').textContent = rem + 's';
    document.getElementById('fillBar').classList.toggle('low', rem <= 7);
    document.getElementById('timerText').classList.toggle('low', rem <= 7);
  } catch(e) {
    document.getElementById('otpDisplay').textContent = 'ERROR';
  }
}

function startTicker() {
  if (ticker) clearInterval(ticker);
  tick();
  ticker = setInterval(tick, 1000);
}

async function copyCode() {
  try {
    const code = await generateTOTP(secret);
    await navigator.clipboard.writeText(code);
    const btn = document.getElementById('copyBtn');
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(function() { btn.textContent = 'Copy Code'; btn.classList.remove('copied'); }, 1800);
  } catch(e) { console.error('copy failed', e); }
}

async function saveKey() {
  const raw   = document.getElementById('secretInput').value.trim().toUpperCase().replace(/\s/g,'');
  const errEl = document.getElementById('errMsg');
  errEl.style.display = 'none';

  if (!raw) {
    errEl.textContent = 'Please enter a secret key.';
    errEl.style.display = 'block';
    return;
  }
  try {
    base32Decode(raw);
    await generateTOTP(raw);
  } catch(e) {
    errEl.textContent = 'Invalid Base32 key — check for typos.';
    errEl.style.display = 'block';
    return;
  }
  await chrome.storage.local.set({ otpSecret: raw });
  secret = raw;
  show('view-ready');
  startTicker();
}

// ── Events ───────────────────────────────────────────────────────────────

document.getElementById('gearBtn')   .addEventListener('click', openSetup);
document.getElementById('addKeyBtn') .addEventListener('click', openSetup);
document.getElementById('copyBtn')   .addEventListener('click', copyCode);
document.getElementById('saveBtn')   .addEventListener('click', saveKey);
document.getElementById('backBtn')   .addEventListener('click', function() {
  show(secret ? 'view-ready' : 'view-nokey');
});
document.getElementById('secretInput').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') saveKey();
});

init();

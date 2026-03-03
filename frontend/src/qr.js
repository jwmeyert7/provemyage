// QR code generation (user → verifier) and scanning (verifier side).
// v2 QR: the proof is uploaded to the backend; the QR carries only a short token.
// v1 QR (legacy): full proof embedded - kept for backwards-compatible scanning.

import QRCode from 'qrcode';
import jsQR from 'jsqr';

// ── Upload credential to backend, get short token ─────────────────────────
async function uploadCredential(credential, backendUrl) {
  const { proof, publicInputs, nullifier, ageRangeLabel, disclosed } = credential;
  const timestamp = Math.floor(Date.now() / 1000);
  const res = await fetch(`${backendUrl}/credentials`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proof, publicInputs, nullifier, timestamp, ageRangeLabel, disclosed }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error ?? `Backend error ${res.status}`);
  }
  return res.json(); // { token, expiresIn }
}

// ── QR generation ─────────────────────────────────────────────────────────

/**
 * Render a QR code into a <canvas> element.
 */
export async function renderQR(payload, canvas, opts = {}) {
  await QRCode.toCanvas(canvas, payload, {
    errorCorrectionLevel: 'M',
    width:    opts.width    ?? 280,
    margin:   opts.margin   ?? 1,
    color: {
      dark:  opts.dark  ?? '#000000',
      light: opts.light ?? '#ffffff',
    },
  });
}

/**
 * High-level helper: upload credential to backend, generate token QR.
 *
 * @param {Object}            credential
 * @param {HTMLCanvasElement} canvas
 * @param {number}            [ttlSeconds=60]
 * @param {string}            [backendUrl]
 * @returns {{ cancel: Function, expiresAt: number }}
 */
export async function showCredentialQR(credential, canvas, ttlSeconds = 60, backendUrl = 'http://localhost:3001') {
  const { token } = await uploadCredential(credential, backendUrl);

  // Compact v2 payload - just the token + age label
  const payload = JSON.stringify({ v: 2, t: token, ar: credential.ageRangeLabel });
  await renderQR(payload, canvas);

  const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;

  // Visual expiry and countdown are handled by main.js (fillStaticNoise + markScannedBtn).
  return { cancel: () => {}, expiresAt };
}

// ── QR scanning ───────────────────────────────────────────────────────────

/**
 * Scan a QR code from a video element frame-by-frame.
 */
export function scanQRFromCamera(videoEl, onFrame) {
  const canvas = document.createElement('canvas');
  const ctx    = canvas.getContext('2d');
  let active   = true;

  const promise = new Promise((resolve, reject) => {
    const scan = () => {
      if (!active) return;
      if (videoEl.readyState < 2) { requestAnimationFrame(scan); return; }

      canvas.width  = videoEl.videoWidth;
      canvas.height = videoEl.videoHeight;
      ctx.drawImage(videoEl, 0, 0);

      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const qr      = jsQR(imgData.data, canvas.width, canvas.height);

      if (qr) {
        try {
          const parsed = parseQRPayload(qr.data);
          // Valid ProveMyAge QR - stop scanning and resolve
          active = false;
          resolve(parsed);
          return;
        } catch {
          // Not a ProveMyAge QR (wrong format, product barcode, etc.) - keep scanning silently
        }
      }

      if (onFrame) onFrame({ scanning: true });
      requestAnimationFrame(scan);
    };

    requestAnimationFrame(scan);

    setTimeout(() => {
      if (active) { active = false; reject(new Error('QR scan timed out.')); }
    }, 120_000);
  });

  const cancel = () => { active = false; };
  return { promise, cancel };
}

/**
 * Scan a QR from a static image file.
 */
export async function scanQRFromFile(file) {
  const bitmap = await createImageBitmap(file);
  const canvas = document.createElement('canvas');
  canvas.width  = bitmap.width;
  canvas.height = bitmap.height;
  canvas.getContext('2d').drawImage(bitmap, 0, 0);
  const imgData = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
  const qr      = jsQR(imgData.data, canvas.width, canvas.height);
  if (!qr) throw new Error('No QR code found in image');
  return parseQRPayload(qr.data);
}

/**
 * Parse and validate a raw QR payload string.
 * Handles both v2 (token) and v1 (legacy full-proof) payloads.
 */
export function parseQRPayload(raw) {
  let data;
  try { data = JSON.parse(raw); } catch { throw new Error('QR code does not contain valid JSON'); }

  if (data.v === 2) {
    // Token-based - backend lookup required for verification
    return {
      version:       2,
      token:         data.t,
      ageRangeLabel: data.ar,
    };
  }

  if (data.v !== 1) throw new Error(`Unknown QR version: ${data.v}`);

  // Legacy v1 full-proof payload
  function fromBase64(b64) {
    return Array.from(atob(b64), c => c.charCodeAt(0));
  }
  return {
    version:       1,
    timestamp:     data.ts,
    ageRangeLabel: data.ar,
    proof:         fromBase64(data.pf),
    publicInputs:  data.pi,
    nullifier:     data.nl,
    faceHash:      data.fh,
    attestation:   { publicKey: data.at.pk, signature: data.at.sg, message: data.at.ms },
  };
}

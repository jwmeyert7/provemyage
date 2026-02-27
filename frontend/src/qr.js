// QR code generation (user → verifier) and scanning (verifier side).
// The QR payload is a compact JSON blob; large proofs are base64-encoded.

import QRCode from 'qrcode';
import jsQR from 'jsqr';

// ── Encoding helpers ─────────────────────────────────────────────────────────
function toBase64(arr) {
  return btoa(String.fromCharCode(...new Uint8Array(arr instanceof Array ? arr : Array.from(arr))));
}

function fromBase64(b64) {
  return Array.from(atob(b64), c => c.charCodeAt(0));
}

// ── QR generation ────────────────────────────────────────────────────────────

/**
 * Build the QR payload from a credential + fresh timestamp + nullifier.
 *
 * IMPORTANT: A fresh QR is generated each time (new timestamp → new nullifier),
 * so the 60-second window is enforced at scan time by the backend.
 *
 * @param {Object} credential - from saveCredential()
 * @param {number} timestamp  - current Unix seconds (must match proof)
 * @returns {string} compact JSON string
 */
export function buildQRPayload(credential, timestamp) {
  const { proof, publicInputs, nullifier, faceHash, ageRangeLabel, attestation } = credential;
  return JSON.stringify({
    v: 1,
    ts: timestamp,
    ar: ageRangeLabel,
    pf: toBase64(proof),
    pi: publicInputs,
    nl: nullifier,
    fh: faceHash,
    at: {
      pk: attestation.publicKey,
      sg: attestation.signature,
      ms: attestation.message,
    },
  });
}

/**
 * Render a QR code into a <canvas> element.
 *
 * @param {string}            payload
 * @param {HTMLCanvasElement} canvas
 * @param {Object}            [opts]
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
 * High-level helper: generate a QR canvas for a credential.
 * Returns the canvas element and a cleanup timer.
 *
 * @param {Object}            credential
 * @param {HTMLCanvasElement} canvas
 * @param {number}            [ttlSeconds=60]
 * @returns {{ cancel: Function, expiresAt: number }}
 */
export async function showCredentialQR(credential, canvas, ttlSeconds = 60) {
  const timestamp = Math.floor(Date.now() / 1000);
  const payload   = buildQRPayload(credential, timestamp);
  await renderQR(payload, canvas);

  const expiresAt = timestamp + ttlSeconds;
  const timer     = setInterval(() => {
    const remaining = expiresAt - Math.floor(Date.now() / 1000);
    if (remaining <= 0) {
      clearInterval(timer);
      // Grey out the canvas to signal expiry
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = 'rgba(255,255,255,0.7)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#ef4444';
      ctx.font = 'bold 18px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('EXPIRED', canvas.width / 2, canvas.height / 2);
    }
  }, 1000);

  return { cancel: () => clearInterval(timer), expiresAt };
}

// ── QR scanning ──────────────────────────────────────────────────────────────

/**
 * Scan a QR code from a video element frame-by-frame.
 * Returns the decoded credential payload object.
 *
 * @param {HTMLVideoElement} videoEl
 * @param {Function} [onFrame] - called each frame with { scanning: true }
 * @returns {Promise<Object>} parsed QR payload
 */
export function scanQRFromCamera(videoEl, onFrame) {
  return new Promise((resolve, reject) => {
    const canvas = document.createElement('canvas');
    const ctx    = canvas.getContext('2d');
    let active   = true;

    const scan = () => {
      if (!active) return;
      if (videoEl.readyState < 2) { requestAnimationFrame(scan); return; }

      canvas.width  = videoEl.videoWidth;
      canvas.height = videoEl.videoHeight;
      ctx.drawImage(videoEl, 0, 0);

      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const qr      = jsQR(imgData.data, canvas.width, canvas.height);

      if (qr) {
        active = false;
        try {
          resolve(parseQRPayload(qr.data));
        } catch (err) {
          reject(err);
        }
        return;
      }

      if (onFrame) onFrame({ scanning: true });
      requestAnimationFrame(scan);
    };

    requestAnimationFrame(scan);

    // Timeout after 120 seconds
    setTimeout(() => {
      if (active) {
        active = false;
        reject(new Error('QR scan timed out. Make sure the QR code is visible.'));
      }
    }, 120_000);
  });
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
 */
export function parseQRPayload(raw) {
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error('QR code does not contain valid JSON');
  }
  if (data.v !== 1) throw new Error(`Unknown QR version: ${data.v}`);
  return {
    timestamp:     data.ts,
    ageRangeLabel: data.ar,
    proof:         fromBase64(data.pf),
    publicInputs:  data.pi,
    nullifier:     data.nl,
    faceHash:      data.fh,
    attestation:   { publicKey: data.at.pk, signature: data.at.sg, message: data.at.ms },
  };
}

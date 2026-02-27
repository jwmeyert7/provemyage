// ProveMyAge — App Orchestrator
// Manages the 4-step credential creation flow and the verifier scan flow.
// All DOM queries use IDs defined in index.html.

import { extractBirthDateFromPassport, thresholdDateForAge, upperBoundDateForAge } from './mrz.js';
import { generateAgeProof, initProver } from './zk.js';
import { captureSelfieHash } from './face.js';
import { createAttestation, saveCredential, listCredentials, randomFieldElement, verifyAttestation } from './crypto.js';
import { showCredentialQR, scanQRFromCamera, scanQRFromFile } from './qr.js';

// ── State ────────────────────────────────────────────────────────────────────
const state = {
  mode: 'create',   // 'create' | 'show' | 'verify'
  step: 1,          // 1–4 for create mode
  birthDate:    null,
  faceHash:     null,
  selfieThumb:  null,
  attestation:  null,
  credential:   null,
  cameraStream: null,
  qrTimer:      null,
};

// ── DOM helpers ──────────────────────────────────────────────────────────────
const $  = id => document.getElementById(id);
const on = (id, ev, fn) => $(id)?.addEventListener(ev, fn);

function setStatus(id, msg, type = 'info') {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.className   = `status status--${type}`;
  el.hidden      = false;
}

function setStep(n) {
  state.step = n;
  document.querySelectorAll('.step-panel').forEach(p => {
    p.hidden = p.dataset.step !== String(n);
  });
  document.querySelectorAll('.step-indicator').forEach(ind => {
    const s = parseInt(ind.dataset.step);
    ind.classList.toggle('active',    s === n);
    ind.classList.toggle('complete',  s  < n);
  });
}

function showMode(mode) {
  state.mode = mode;
  document.querySelectorAll('.mode-panel').forEach(p => {
    p.hidden = p.dataset.mode !== mode;
  });
  if (mode === 'create') setStep(1);
}

async function stopCamera() {
  if (state.cameraStream) {
    state.cameraStream.getTracks().forEach(t => t.stop());
    state.cameraStream = null;
  }
}

// ── Step 1: Passport OCR ─────────────────────────────────────────────────────
function initStep1() {
  on('passportUpload', 'change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setStatus('s1-status', 'Scanning passport MRZ… (local OCR, no upload)', 'info');
    $('s1-progress').hidden = false;

    try {
      state.birthDate = await extractBirthDateFromPassport(file, pct => {
        const bar = $('s1-progress-bar');
        if (bar) bar.style.width = `${pct}%`;
      });

      setStatus('s1-status', `Birth year verified: ${state.birthDate.birthYear} ✓`, 'success');
      $('s1-progress').hidden = true;
      setTimeout(() => setStep(2), 800);
    } catch (err) {
      setStatus('s1-status', `Error: ${err.message}`, 'error');
      $('s1-progress').hidden = true;
    }
  });

  on('passportCameraBtn', 'click', async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' }, width: 1280 }
      });
      state.cameraStream = stream;
      const video = $('passport-video');
      video.srcObject = stream;
      video.hidden = false;
      $('capturePassportBtn').hidden = false;
    } catch (err) {
      setStatus('s1-status', `Camera error: ${err.message}`, 'error');
    }
  });

  on('capturePassportBtn', 'click', async () => {
    const video  = $('passport-video');
    const canvas = document.createElement('canvas');
    canvas.width  = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    stopCamera();
    video.hidden = true;
    $('capturePassportBtn').hidden = true;

    setStatus('s1-status', 'Scanning MRZ…', 'info');
    try {
      canvas.toBlob(async (blob) => {
        state.birthDate = await extractBirthDateFromPassport(blob);
        setStatus('s1-status', `Birth year verified: ${state.birthDate.birthYear} ✓`, 'success');
        setTimeout(() => setStep(2), 800);
      }, 'image/jpeg');
    } catch (err) {
      setStatus('s1-status', `Error: ${err.message}`, 'error');
    }
  });
}

// ── Step 2: Selfie / Face Hash ───────────────────────────────────────────────
function initStep2() {
  on('selfieBtn', 'click', async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' } });
      state.cameraStream = stream;
      const video = $('selfie-video');
      video.srcObject = stream;
      video.hidden = false;
      $('captureSelfieBtn').hidden = false;
      setStatus('s2-status', 'Position your face in the frame', 'info');
    } catch (err) {
      setStatus('s2-status', `Camera error: ${err.message}`, 'error');
    }
  });

  on('captureSelfieBtn', 'click', async () => {
    const video = $('selfie-video');
    setStatus('s2-status', 'Computing face hash locally…', 'info');
    $('captureSelfieBtn').disabled = true;

    try {
      const { faceHash, thumbnail } = await captureSelfieHash(video);
      state.faceHash    = faceHash;
      state.selfieThumb = thumbnail;

      stopCamera();
      video.hidden = true;
      $('captureSelfieBtn').hidden = true;

      const thumb = $('selfie-thumb');
      if (thumb) { thumb.src = thumbnail; thumb.hidden = false; }

      setStatus('s2-status', `Face hash computed ✓ (${faceHash.slice(0, 16)}…)`, 'success');
      setTimeout(() => setStep(3), 800);
    } catch (err) {
      setStatus('s2-status', `Error: ${err.message}`, 'error');
      $('captureSelfieBtn').disabled = false;
    }
  });
}

// ── Step 3: Legal Attestation ────────────────────────────────────────────────
function initStep3() {
  on('attestBtn', 'click', async () => {
    const checked = $('attestCheckbox')?.checked;
    if (!checked) {
      setStatus('s3-status', 'You must check the box to proceed', 'error');
      return;
    }

    setStatus('s3-status', 'Signing attestation with your device key…', 'info');

    try {
      const nullifierSeedHex = randomFieldElement();
      state.nullifierSeed    = nullifierSeedHex;

      // Default label; will be set in step 4
      state.attestation = await createAttestation({
        faceHash:      state.faceHash,
        ageRangeLabel: 'TBD',
        nullifierSeedHex,
      });

      const sigPreview = $('sig-preview');
      if (sigPreview) {
        sigPreview.textContent = state.attestation.signature.slice(0, 32) + '…';
      }

      setStatus('s3-status', 'Attestation signed ✓', 'success');
      setTimeout(() => setStep(4), 800);
    } catch (err) {
      setStatus('s3-status', `Signing failed: ${err.message}`, 'error');
    }
  });
}

// ── Step 4: Choose age threshold + Generate Proof ────────────────────────────
const AGE_PRESETS = [
  { label: '13+',      min: 13, max: null },
  { label: '18+',      min: 18, max: null },
  { label: '21+',      min: 21, max: null },
  { label: '25+',      min: 25, max: null },
  { label: 'Under 18', min: null, max: 17  },
];

function initStep4() {
  let selectedPreset = AGE_PRESETS[1]; // default 18+

  // Wire preset buttons
  document.querySelectorAll('.age-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.age-preset-btn').forEach(b => b.classList.remove('selected'));
      btn.classList.add('selected');
      const idx = parseInt(btn.dataset.preset);
      selectedPreset = AGE_PRESETS[idx];
      $('custom-range-panel').hidden = true;
    });
  });

  // Custom range toggle
  on('customRangeBtn', 'click', () => {
    document.querySelectorAll('.age-preset-btn').forEach(b => b.classList.remove('selected'));
    $('custom-range-panel').hidden = false;
    selectedPreset = null;
  });

  // Generate proof
  on('generateProofBtn', 'click', async () => {
    // Resolve age range
    let minAge = null, maxAge = null, ageRangeLabel = '';
    if (selectedPreset) {
      minAge = selectedPreset.min;
      maxAge = selectedPreset.max;
      ageRangeLabel = selectedPreset.label;
    } else {
      minAge = parseInt($('custom-min')?.value) || null;
      maxAge = parseInt($('custom-max')?.value) || null;
      if (!minAge && !maxAge) {
        setStatus('s4-status', 'Enter a minimum or maximum age', 'error');
        return;
      }
      ageRangeLabel = minAge && maxAge ? `${minAge}–${maxAge}`
                    : minAge           ? `${minAge}+`
                    :                    `Under ${maxAge + 1}`;
    }

    // Compute threshold dates
    const now       = Math.floor(Date.now() / 1000);
    const threshold = minAge ? thresholdDateForAge(minAge) : { year: 9999, month: 12, day: 31 };
    const upper     = maxAge ? upperBoundDateForAge(maxAge) : null;

    $('generateProofBtn').disabled = true;
    $('proof-progress').hidden     = false;

    const setS = msg => setStatus('s4-status', msg, 'info');

    try {
      // Pre-warm the prover so UI shows feedback early
      await initProver(setS);

      const { proof, publicInputs, nullifier } = await generateAgeProof({
        birthYear:  state.birthDate.birthYear,
        birthMonth: state.birthDate.birthMonth,
        birthDay:   state.birthDate.birthDay,
        nullifierSeed:   state.nullifierSeed,
        thresholdYear:   threshold.year,
        thresholdMonth:  threshold.month,
        thresholdDay:    threshold.day,
        faceHash:        state.faceHash,
        currentTimestamp: now,
        hasUpperBound:    !!upper,
        upperYear:  upper?.year  ?? 0,
        upperMonth: upper?.month ?? 0,
        upperDay:   upper?.day   ?? 0,
        onStatus:   setS,
      });

      // Build & store credential
      const credential = {
        proof, publicInputs, nullifier,
        faceHash:      state.faceHash,
        ageRangeLabel,
        attestation:   state.attestation,
        nullifierSeed: state.nullifierSeed,
        createdAt:     Date.now(),
      };
      const id = await saveCredential(credential);
      state.credential = { ...credential, id };

      setStatus('s4-status', `Credential created ✓ — ${ageRangeLabel}`, 'success');
      $('proof-progress').hidden = true;

      // Switch to QR display mode
      setTimeout(() => showMode('show'), 500);
    } catch (err) {
      setStatus('s4-status', `Error: ${err.message}`, 'error');
      $('generateProofBtn').disabled = false;
      $('proof-progress').hidden     = true;
    }
  });
}

// ── Show QR mode ─────────────────────────────────────────────────────────────
let qrCountdownInterval = null;

async function enterShowMode() {
  if (!state.credential) {
    // Try loading most recent saved credential
    const creds = await listCredentials();
    if (creds.length === 0) { showMode('create'); return; }
    state.credential = creds.sort((a, b) => b.createdAt - a.createdAt)[0];
  }

  const canvas = $('qr-canvas');
  const label  = $('qr-age-label');
  if (label) label.textContent = state.credential.ageRangeLabel;

  if (state.qrTimer) { state.qrTimer.cancel(); }
  const { cancel, expiresAt } = await showCredentialQR(state.credential, canvas);
  state.qrTimer = { cancel };

  // Countdown display
  if (qrCountdownInterval) clearInterval(qrCountdownInterval);
  qrCountdownInterval = setInterval(() => {
    const remaining = expiresAt - Math.floor(Date.now() / 1000);
    const el = $('qr-countdown');
    if (el) el.textContent = remaining > 0 ? `${remaining}s` : 'EXPIRED';
  }, 500);

  on('refreshQrBtn', 'click', async () => {
    if (state.qrTimer) state.qrTimer.cancel();
    clearInterval(qrCountdownInterval);
    await enterShowMode();
  });
}

// ── Verify mode ──────────────────────────────────────────────────────────────
function initVerifyMode() {
  on('startScanBtn', 'click', async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      state.cameraStream = stream;
      const video = $('scan-video');
      video.srcObject = stream;
      video.hidden    = false;

      setStatus('verify-status', 'Scanning for QR code…', 'info');

      const payload = await scanQRFromCamera(video, () => {});
      stopCamera();
      video.hidden = true;

      await handleVerification(payload);
    } catch (err) {
      setStatus('verify-status', `Scan error: ${err.message}`, 'error');
    }
  });

  on('scanFileInput', 'change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const payload = await scanQRFromFile(file);
      await handleVerification(payload);
    } catch (err) {
      setStatus('verify-status', `Error: ${err.message}`, 'error');
    }
  });
}

async function handleVerification(payload) {
  setStatus('verify-status', 'Sending proof to verifier backend…', 'info');

  const apiKey = $('api-key-input')?.value?.trim();
  const backendUrl = $('backend-url-input')?.value?.trim() ?? 'http://localhost:3001';

  try {
    const res = await fetch(`${backendUrl}/verify`, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${apiKey ?? 'demo'}`,
      },
      body: JSON.stringify({
        proof:         payload.proof,
        publicInputs:  payload.publicInputs,
        nullifier:     payload.nullifier,
        timestamp:     payload.timestamp,
        ageRangeLabel: payload.ageRangeLabel,
      }),
    });

    const result = await res.json();

    if (result.verified) {
      showVerifyResult(true, payload.ageRangeLabel, payload.attestation);
    } else {
      showVerifyResult(false, result.reason ?? 'Verification failed');
    }
  } catch (err) {
    // Fallback: local proof verification (no nullifier check)
    try {
      const { verifyProofLocally } = await import('./zk.js');
      const valid = await verifyProofLocally({ proof: payload.proof, publicInputs: payload.publicInputs });
      showVerifyResult(valid, valid ? `${payload.ageRangeLabel} (local, no nullifier check)` : 'Invalid proof');
    } catch {
      setStatus('verify-status', `Backend error: ${err.message}`, 'error');
    }
  }
}

async function showVerifyResult(ok, label, attestation) {
  const panel = $('verify-result');
  const icon  = $('result-icon');
  const text  = $('result-text');

  panel.hidden       = false;
  icon.textContent   = ok ? '✓' : '✗';
  icon.className     = ok ? 'result-icon result-icon--ok' : 'result-icon result-icon--fail';
  text.textContent   = ok ? `Verified: ${label}` : `Failed: ${label}`;

  if (ok && attestation) {
    const valid = await verifyAttestation(attestation);
    $('attestation-status').textContent = valid ? '✓ Legal attestation valid' : '⚠ Attestation signature invalid';
  }
}

// ── Dark / light mode ────────────────────────────────────────────────────────
function initTheme() {
  const stored = localStorage.getItem('theme') ?? 'light';
  document.documentElement.dataset.theme = stored;

  on('themeToggle', 'click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('theme', next);
    $('themeToggle').textContent = next === 'dark' ? '☀' : '🌙';
  });
}

// ── Nav ──────────────────────────────────────────────────────────────────────
function initNav() {
  on('createModeBtn', 'click', () => showMode('create'));
  on('showModeBtn',   'click', async () => {
    showMode('show');
    await enterShowMode();
  });
  on('verifyModeBtn', 'click', () => { stopCamera(); showMode('verify'); });
}

// ── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initNav();
  initStep1();
  initStep2();
  initStep3();
  initStep4();
  initVerifyMode();

  showMode('create');
  setStep(1);

  // Pre-warm the prover in the background so step 4 is faster
  setTimeout(() => initProver(), 2000);
});

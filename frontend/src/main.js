// ProveMyAge - App Orchestrator
// Manages the 3-step credential creation flow and the verifier scan flow.
// Selfie step removed: face_hash is a fixed dummy value (the circuit still
// accepts it as a public input; the ZK proof proves age, not identity).

import { extractBirthDateFromPassport, thresholdDateForAge, upperBoundDateForAge } from './mrz.js';
import { generateAgeProof, initProver, packNationality, packGender, packNameToField } from './zk.js';
import { createAttestation, saveCredential, listCredentials, randomFieldElement, verifyAttestation } from './crypto.js';
import { showCredentialQR, scanQRFromCamera, scanQRFromFile } from './qr.js';

const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
function formatBirthdate(bd) {
  return `${MONTHS[bd.birthMonth - 1]} ${bd.birthDay}, ${bd.birthYear}`;
}
function computeAge(bd) {
  const d = new Date();
  const y = d.getUTCFullYear(), m = d.getUTCMonth() + 1, day = d.getUTCDate();
  let age = y - bd.birthYear;
  if (m < bd.birthMonth || (m === bd.birthMonth && day < bd.birthDay)) age--;
  return age;
}

// Populate disclosure checkbox preview values from parsed MRZ data
function populateDisclosurePreviews() {
  const bd = state.birthDate;
  if (!bd) return;
  const bv = $('disc-birthdate-val');
  if (bv) bv.textContent = `(${formatBirthdate(bd)})`;
  const av = $('disc-age-val');
  if (av) av.textContent = `(${computeAge(bd)})`;
  const nv = $('disc-nationality-val');
  if (nv) nv.textContent = bd.nationality ? `(${bd.nationality})` : '';
  const gv = $('disc-gender-val');
  if (gv) gv.textContent = bd.gender ? `(${bd.gender})` : '(not specified)';
  const nmv = $('disc-name-val');
  if (nmv) {
    const name = [bd.surname, bd.givenNames].filter(Boolean).join(', ');
    nmv.textContent = name ? `(${name})` : '';
  }
}

// Dummy face hash - 31 zero bytes, valid BN254 field element
const DUMMY_FACE_HASH = '0x' + '00'.repeat(31);

// ── State ────────────────────────────────────────────────────────────────────
const state = {
  mode: 'create',   // 'create' | 'show' | 'verify'
  step: 1,          // 1-3 for create mode
  birthDate:    null,
  faceHash:     DUMMY_FACE_HASH,
  attestation:  null,
  credential:   null,
  nullifierSeed: null,
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
  // Sync active highlight on nav buttons
  $('createModeBtn')?.classList.toggle('active', mode === 'create' || mode === 'show');
  $('verifyModeBtn')?.classList.toggle('active', mode === 'verify');
  $('faqModeBtn')?.classList.toggle('active', mode === 'faq');
  if (mode === 'create') setStep(state.step || 1);
}

async function stopCamera() {
  if (state.cameraStream) {
    state.cameraStream.getTracks().forEach(t => t.stop());
    state.cameraStream = null;
  }
}

// ── Start over ────────────────────────────────────────────────────────────────
function startOver() {
  stopCamera();
  if (state.qrTimer) { state.qrTimer.cancel(); state.qrTimer = null; }

  state.birthDate    = null;
  state.faceHash     = DUMMY_FACE_HASH;
  state.attestation  = null;
  state.credential   = null;
  state.nullifierSeed = null;
  state.step         = 1;

  // Clear passport preview
  const preview = $('passport-preview');
  if (preview) preview.remove();

  // Reset file inputs
  const pu = $('passportUpload');
  if (pu) pu.value = '';

  // Clear all status elements
  ['s1-status', 's2-status', 's3-status'].forEach(id => {
    const el = $(id);
    if (el) { el.hidden = true; el.textContent = ''; }
  });
  const prog = $('s1-progress');
  if (prog) prog.hidden = true;

  // Clear attestation checkbox and birthdate display
  const cb = $('attestCheckbox');
  if (cb) cb.checked = false;
  const sig = $('sig-preview');
  if (sig) sig.textContent = '';
  const bdEl = $('attest-birthdate-display');
  if (bdEl) { bdEl.hidden = true; bdEl.textContent = ''; }
  const ps = $('proof-summary');
  if (ps) { ps.hidden = true; ps.innerHTML = ''; }
  // Reset disclosure checkboxes
  ['disc-birthdate','disc-age','disc-nationality','disc-gender','disc-name'].forEach(id => {
    const cb = $(id);
    if (cb) cb.checked = false;
  });
  ['disc-birthdate-val','disc-age-val','disc-nationality-val','disc-gender-val','disc-name-val'].forEach(id => {
    const el = $(id);
    if (el) el.textContent = '';
  });
  const cs = $('qr-cred-summary');
  if (cs) cs.hidden = true;
  const msBtn = $('markScannedBtn');
  if (msBtn) { msBtn.hidden = true; msBtn.onclick = null; }
  // Clean up any blob URL on the download link
  const dl = $('cs-download');
  if (dl?._blobUrl) { URL.revokeObjectURL(dl._blobUrl); dl._blobUrl = null; }

  // Reset passport video
  const pv = $('passport-video');
  if (pv) { pv.hidden = true; pv.srcObject = null; }
  const cpb = $('capturePassportBtn');
  if (cpb) cpb.hidden = true;

  showMode('create');
  setStep(1);
}

// ── Step 1: Passport OCR ──────────────────────────────────────────────────────
function initStep1() {
  on('passportUpload', 'change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Show a thumbnail immediately so the user knows the file was received
    const reader = new FileReader();
    reader.onload = ev => {
      let preview = $('passport-preview');
      if (!preview) {
        preview = document.createElement('img');
        preview.id = 'passport-preview';
        preview.style.cssText = 'width:100%;border-radius:8px;margin-top:.75rem;max-height:200px;object-fit:contain;background:#000';
        $('passportUpload').closest('label').after(preview);
      }
      preview.src = ev.target.result;
    };
    reader.readAsDataURL(file);

    setStatus('s1-status', 'Scanning passport MRZ... (local OCR, no upload)', 'info');
    $('s1-progress').hidden = false;

    try {
      const timeout = new Promise((_, rej) =>
        setTimeout(() => rej(new Error('Birthdate not found. Make sure the photo shows the full MRZ strip at the bottom of the passport photo page.')), 60_000)
      );
      state.birthDate = await Promise.race([
        extractBirthDateFromPassport(file, pct => {
          const bar = $('s1-progress-bar');
          if (bar) bar.style.width = `${pct}%`;
        }),
        timeout,
      ]);

      setStatus('s1-status', `Birthdate confirmed: ${formatBirthdate(state.birthDate)} \u2713`, 'success');
      $('s1-progress').hidden = true;
      populateDisclosurePreviews();
      setTimeout(() => {
        setStep(2);
        const bdEl = $('attest-birthdate-display');
        if (bdEl) {
          bdEl.textContent = `Passport birthdate: ${formatBirthdate(state.birthDate)}`;
          bdEl.hidden = false;
        }
      }, 800);
    } catch (err) {
      setStatus('s1-status', err.message.startsWith('Birthdate') ? err.message : `Error: ${err.message}`, 'error');
      $('s1-progress').hidden = true;
    }
  });

  on('passportCameraBtn', 'click', async () => {
    if (!navigator.mediaDevices?.getUserMedia) {
      setStatus('s1-status', 'Live camera requires HTTPS. Tap the upload area above - your device will offer a "Take Photo" option.', 'error');
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' }, width: 1280 }
      });
      state.cameraStream = stream;
      const video = $('passport-video');
      video.srcObject = stream;
      video.hidden = false;
      $('capturePassportBtn').hidden = false;
      $('passportCameraBtn').hidden  = true;
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
    $('passportCameraBtn').hidden  = false;

    setStatus('s1-status', 'Scanning MRZ...', 'info');
    canvas.toBlob(async (blob) => {
      try {
        const timeout = new Promise((_, rej) =>
          setTimeout(() => rej(new Error('Birthdate not found. Make sure the photo shows the full MRZ strip at the bottom of the passport photo page.')), 60_000)
        );
        state.birthDate = await Promise.race([extractBirthDateFromPassport(blob), timeout]);
        setStatus('s1-status', `Birthdate confirmed: ${formatBirthdate(state.birthDate)} \u2713`, 'success');
        populateDisclosurePreviews();
        setTimeout(() => {
          setStep(2);
          const bdEl = $('attest-birthdate-display');
          if (bdEl) {
            bdEl.textContent = `Passport birthdate: ${formatBirthdate(state.birthDate)}`;
            bdEl.hidden = false;
          }
        }, 800);
      } catch (err) {
        setStatus('s1-status', err.message.startsWith('Birthdate') ? err.message : `Error: ${err.message}`, 'error');
      }
    }, 'image/jpeg');
  });
}

// ── Step 2: Legal Attestation ──────────────────────────────────────────────────
function initStep2() {
  on('attestBtn', 'click', async () => {
    const checked = $('attestCheckbox')?.checked;
    if (!checked) {
      setStatus('s2-status', 'You must check the box to proceed', 'error');
      return;
    }

    setStatus('s2-status', 'Signing attestation with your device key...', 'info');

    try {
      const nullifierSeedHex = randomFieldElement();
      state.nullifierSeed    = nullifierSeedHex;

      state.attestation = await createAttestation({
        faceHash:      state.faceHash,
        ageRangeLabel: 'TBD',
        nullifierSeedHex,
      });

      const sigPreview = $('sig-preview');
      if (sigPreview) {
        sigPreview.textContent = state.attestation.signature.slice(0, 32) + '...';
      }

      setStatus('s2-status', 'Attestation signed \u2713', 'success');
      setTimeout(() => setStep(3), 800);
    } catch (err) {
      setStatus('s2-status', `Signing failed: ${err.message}`, 'error');
    }
  });
}

// ── Step 3: Choose age threshold + Generate Proof ──────────────────────────────
const AGE_PRESETS = [
  { label: '13+',      min: 13, max: null },
  { label: '18+',      min: 18, max: null },
  { label: '21+',      min: 21, max: null },
  { label: '25+',      min: 25, max: null },
  { label: 'Under 18', min: null, max: 17  },
];

function initStep3() {
  let selectedPreset = AGE_PRESETS[1]; // default 18+

  document.querySelectorAll('.age-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.age-preset-btn').forEach(b => b.classList.remove('selected'));
      btn.classList.add('selected');
      const idx = parseInt(btn.dataset.preset);
      selectedPreset = AGE_PRESETS[idx];
      $('custom-range-panel').hidden = true;
    });
  });

  on('customRangeBtn', 'click', () => {
    document.querySelectorAll('.age-preset-btn').forEach(b => b.classList.remove('selected'));
    $('custom-range-panel').hidden = false;
    selectedPreset = null;
  });

  on('generateProofBtn', 'click', async () => {
    let minAge = null, maxAge = null, ageRangeLabel = '';
    if (selectedPreset) {
      minAge = selectedPreset.min;
      maxAge = selectedPreset.max;
      ageRangeLabel = selectedPreset.label;
    } else {
      minAge = parseInt($('custom-min')?.value) || null;
      maxAge = parseInt($('custom-max')?.value) || null;
      if (!minAge && !maxAge) {
        setStatus('s3-status', 'Enter a minimum or maximum age', 'error');
        return;
      }
      ageRangeLabel = minAge && maxAge ? `${minAge}-${maxAge}`
                    : minAge           ? `${minAge}+`
                    :                    `Under ${maxAge + 1}`;
    }

    const now       = Math.floor(Date.now() / 1000);
    const threshold = minAge ? thresholdDateForAge(minAge) : { year: 9999, month: 12, day: 31 };
    const upper     = maxAge ? upperBoundDateForAge(maxAge) : null;

    // Read selective disclosure flags
    const revealBirthdate   = $('disc-birthdate')?.checked ?? false;
    const revealAge         = $('disc-age')?.checked ?? false;
    const revealNationality = $('disc-nationality')?.checked ?? false;
    const revealGender      = $('disc-gender')?.checked ?? false;
    const revealName        = $('disc-name')?.checked ?? false;

    // Encode MRZ fields for the circuit
    const bd = state.birthDate;
    const nationalityCode = packNationality(bd.nationality || '');
    const genderCode      = packGender(bd.gender);
    const mrzName = [bd.surname || '', bd.givenNames || ''].join('<<');
    const namePart1 = packNameToField(mrzName.slice(0, 31));
    const namePart2 = packNameToField(mrzName.slice(31, 62));

    const refDate = new Date();
    const refYear  = refDate.getUTCFullYear();
    const refMonth = refDate.getUTCMonth() + 1;
    const refDay   = refDate.getUTCDate();

    $('generateProofBtn').disabled = true;
    $('proof-progress').hidden     = false;

    const setS = msg => setStatus('s3-status', msg, 'info');

    try {
      await initProver(setS);

      const proofStart = performance.now();
      const { proof, publicInputs, nullifier, disclosed } = await generateAgeProof({
        birthYear:  bd.birthYear,
        birthMonth: bd.birthMonth,
        birthDay:   bd.birthDay,
        nullifierSeed:    state.nullifierSeed,
        thresholdYear:    threshold.year,
        thresholdMonth:   threshold.month,
        thresholdDay:     threshold.day,
        faceHash:         state.faceHash,
        currentTimestamp: now,
        hasUpperBound:    !!upper,
        upperYear:  upper?.year  ?? 0,
        upperMonth: upper?.month ?? 0,
        upperDay:   upper?.day   ?? 0,
        nationalityCode,
        genderCode,
        namePart1,
        namePart2,
        refYear,
        refMonth,
        refDay,
        revealBirthdate,
        revealAge,
        revealNationality,
        revealGender,
        revealName,
        onStatus:   setS,
      });

      const credential = {
        proof, publicInputs, nullifier,
        faceHash:      state.faceHash,
        ageRangeLabel,
        attestation:   state.attestation,
        nullifierSeed: state.nullifierSeed,
        createdAt:     Date.now(),
        disclosed,
      };
      const id = await saveCredential(credential);
      state.credential = { ...credential, id };

      const proofTime = ((performance.now() - proofStart) / 1000).toFixed(1);
      setStatus('s3-status', `Credential created \u2713 - ${ageRangeLabel} (${proofTime}s)`, 'success');
      $('proof-progress').hidden     = true;
      $('generateProofBtn').disabled = false;

      // Show cryptographic summary
      const summary = $('proof-summary');
      if (summary) {
        const nullFp = nullifier.slice(0, 10) + '...' + nullifier.slice(-8);
        const proofBytes = proof.length.toLocaleString();
        let html = `
          <div class="proof-summary-row"><span class="proof-summary-label">Threshold</span><span class="proof-summary-value">${ageRangeLabel}</span></div>
          <div class="proof-summary-row"><span class="proof-summary-label">Credential ID</span><span class="proof-summary-value mono-accent">${nullFp}</span></div>
          <div class="proof-summary-row"><span class="proof-summary-label">Proof size</span><span class="proof-summary-value">${proofBytes} bytes</span></div>
          <div class="proof-summary-row"><span class="proof-summary-label">Public inputs</span><span class="proof-summary-value">${publicInputs.length} fields</span></div>
          <div class="proof-summary-row"><span class="proof-summary-label">Proof time</span><span class="proof-summary-value">${proofTime}s</span></div>
        `;
        if (disclosed && Object.keys(disclosed).length > 0) {
          html += '<div style="margin-top:.4rem;padding-top:.4rem;border-top:1px solid var(--border)">';
          html += '<div class="proof-summary-row"><span class="proof-summary-label" style="font-weight:700">Disclosed fields</span><span class="proof-summary-value"></span></div>';
          if (disclosed.birthdate) html += `<div class="proof-summary-row"><span class="proof-summary-label">Birthdate</span><span class="proof-summary-value">${MONTHS[disclosed.birthdate.month - 1]} ${disclosed.birthdate.day}, ${disclosed.birthdate.year}</span></div>`;
          if (disclosed.age != null) html += `<div class="proof-summary-row"><span class="proof-summary-label">Age</span><span class="proof-summary-value">${disclosed.age}</span></div>`;
          if (disclosed.nationality) html += `<div class="proof-summary-row"><span class="proof-summary-label">Nationality</span><span class="proof-summary-value">${disclosed.nationality}</span></div>`;
          if (disclosed.gender) html += `<div class="proof-summary-row"><span class="proof-summary-label">Gender</span><span class="proof-summary-value">${disclosed.gender}</span></div>`;
          if (disclosed.name) html += `<div class="proof-summary-row"><span class="proof-summary-label">Name</span><span class="proof-summary-value">${disclosed.name}</span></div>`;
          html += '</div>';
        }
        summary.innerHTML = html;
        summary.hidden = false;
      }

      // Switch to QR display mode and render QR immediately
      setTimeout(async () => {
        showMode('show');
        await enterShowMode();
      }, 500);
    } catch (err) {
      const msg = err.message?.includes('Cannot satisfy constraint')
        ? 'Age not verified: you do not meet this age threshold.'
        : `Error: ${err.message}`;
      setStatus('s3-status', msg, 'error');
      $('generateProofBtn').disabled = false;
      $('proof-progress').hidden     = true;
    }
  });
}

// ── Static noise visual on QR expiry ─────────────────────────────────────────
function fillStaticNoise(canvas) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  const imageData = ctx.createImageData(w, h);
  const data = imageData.data;
  for (let i = 0; i < data.length; i += 4) {
    const v = (Math.random() * 160 + 40) | 0;
    data[i] = data[i+1] = data[i+2] = v;
    data[i+3] = 255;
  }
  ctx.putImageData(imageData, 0, 0);
  // Dark vignette
  const grad = ctx.createRadialGradient(w/2, h/2, w*0.2, w/2, h/2, w*0.7);
  grad.addColorStop(0, 'rgba(0,0,0,0)');
  grad.addColorStop(1, 'rgba(0,0,0,0.6)');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, w, h);
  // "USED" label
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.font = 'bold 22px monospace';
  ctx.fillStyle = 'rgba(255,255,255,0.85)';
  ctx.fillText('USED', w/2, h/2);
}

// ── Show QR mode ───────────────────────────────────────────────────────────────
let qrCountdownInterval = null;

async function enterShowMode() {
  if (!state.credential) {
    const creds = await listCredentials();
    if (creds.length === 0) { showMode('create'); return; }
    state.credential = creds.sort((a, b) => b.createdAt - a.createdAt)[0];
  }

  const canvas = $('qr-canvas');
  const label  = $('qr-age-label');
  if (label) label.textContent = state.credential.ageRangeLabel;

  // Show loading state
  if (canvas) {
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'var(--border, #e5e7eb)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'var(--text-muted, #6b7280)';
    ctx.font = '14px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Generating QR...', canvas.width / 2, canvas.height / 2);
  }

  if (state.qrTimer) { state.qrTimer.cancel(); state.qrTimer = null; }
  if (qrCountdownInterval) { clearInterval(qrCountdownInterval); qrCountdownInterval = null; }

  const backendUrl = $('backend-url-input')?.value?.trim() || 'https://provemyage-backend-production.up.railway.app';

  // Populate credential record panel
  const cred = state.credential;
  if (cred && $('qr-cred-summary')) {
    const nullFp   = cred.nullifier.slice(0, 10) + '...' + cred.nullifier.slice(-8);
    const genDate  = new Date(cred.createdAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    const thEl     = $('cs-threshold');
    const idEl     = $('cs-credid');
    const genEl    = $('cs-generated');
    const copyBtn  = $('cs-copy');
    const dlLink   = $('cs-download');

    if (thEl)  thEl.textContent  = cred.ageRangeLabel;
    if (idEl)  idEl.textContent  = nullFp;
    if (genEl) genEl.textContent = genDate;

    if (copyBtn) {
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(cred.nullifier)
          .then(() => { copyBtn.textContent = 'Copied!'; setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000); })
          .catch(() => { copyBtn.textContent = 'Error'; setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000); });
      };
    }

    if (dlLink) {
      const lines = [
        'ProveMyAge Credential Record',
        '============================',
        '',
        'Age threshold : ' + cred.ageRangeLabel,
        'Credential ID : ' + cred.nullifier,
        'Generated     : ' + new Date(cred.createdAt).toISOString(),
        'Proof size    : ' + cred.proof.length + ' bytes',
        'Public inputs : ' + cred.publicInputs.length + ' fields',
        '',
        'This file is for your personal records.',
        'The credential ID is the unique nullifier produced by the ZK proof.',
      ].join('\n');
      if (dlLink._blobUrl) URL.revokeObjectURL(dlLink._blobUrl);
      const blob = new Blob([lines], { type: 'text/plain' });
      dlLink._blobUrl  = URL.createObjectURL(blob);
      dlLink.href      = dlLink._blobUrl;
      dlLink.download  = 'provemyage-' + cred.ageRangeLabel.replace(/[^a-z0-9]/gi, '') + '-' + Date.now() + '.txt';
    }

    $('qr-cred-summary').hidden = false;
  }

  try {
    const { cancel, expiresAt } = await showCredentialQR(state.credential, canvas, 90, backendUrl);
    state.qrTimer = { cancel };

    const msBtn = $('markScannedBtn');
    if (msBtn) msBtn.hidden = false;

    let dead = false;
    function killCredential(reason) {
      if (dead) return;
      dead = true;
      clearInterval(qrCountdownInterval);
      qrCountdownInterval = null;
      if (state.qrTimer) { state.qrTimer.cancel(); state.qrTimer = null; }
      if (canvas) fillStaticNoise(canvas);
      // Replace the whole countdown line - avoids "Expires in Used"
      const countWrap = $('qr-countdown')?.parentElement;
      if (countWrap) countWrap.innerHTML = `<strong>${reason}</strong>`;
      if (msBtn) msBtn.hidden = true;
    }

    if (msBtn) msBtn.onclick = () => killCredential('Used');

    qrCountdownInterval = setInterval(() => {
      const remaining = expiresAt - Math.floor(Date.now() / 1000);
      if (remaining <= 0) {
        killCredential('Expired');
      } else {
        const el = $('qr-countdown');
        if (el) el.textContent = `${remaining}s`;
      }
    }, 500);
  } catch (err) {
    if (canvas) {
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#ef4444';
      ctx.font = '13px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('QR error: ' + err.message, canvas.width / 2, canvas.height / 2);
    }
    console.error('[enterShowMode] QR generation failed:', err.message);
  }
}

// ── Verify mode ────────────────────────────────────────────────────────────────
function initVerifyMode() {
  let activeScanCancel = null;
  let verifying = false;

  function stopActiveScan() {
    if (activeScanCancel) { activeScanCancel(); activeScanCancel = null; }
    stopCamera();
    const video = $('scan-video');
    if (video) { video.hidden = true; video.srcObject = null; }
    const btn = $('startScanBtn');
    if (btn) { btn.textContent = '📷 Scan QR'; btn.disabled = false; }
  }

  on('startScanBtn', 'click', async () => {
    // Block new scans while verification is in progress
    if (verifying) return;

    // If camera is already active, toggle it off
    if (activeScanCancel) {
      stopActiveScan();
      $('verify-status').hidden = true;
      return;
    }

    if (!navigator.mediaDevices?.getUserMedia) {
      setStatus('verify-status', 'Live camera requires HTTPS. Use "Upload image" to scan a screenshot of the QR code instead.', 'error');
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      state.cameraStream = stream;
      const video = $('scan-video');
      video.srcObject = stream;
      video.hidden = false;
      $('startScanBtn').textContent = '⏹ Stop camera';

      setStatus('verify-status', 'Scanning for QR code...', 'info');

      const { promise, cancel } = scanQRFromCamera(video, () => {});
      activeScanCancel = cancel;

      const payload = await promise;
      activeScanCancel = null;
      stopActiveScan();

      // Lock UI during backend verification
      verifying = true;
      $('startScanBtn').disabled = true;
      try {
        await handleVerification(payload);
      } finally {
        verifying = false;
        $('startScanBtn').disabled = false;
      }
    } catch (err) {
      stopActiveScan();
      verifying = false;
      $('startScanBtn').disabled = false;
      if (err.message !== 'QR scan timed out.') {
        setStatus('verify-status', `Scan error: ${err.message}`, 'error');
      } else {
        $('verify-status').hidden = true;
      }
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
  const verifyStart = performance.now();
  setStatus('verify-status', 'Sending proof to verifier backend...', 'info');

  const backendUrl = $('backend-url-input')?.value?.trim() || 'https://provemyage-backend-production.up.railway.app';

  try {
    let body;
    if (payload.version === 2) {
      // Token-based QR: backend looks up stored credential
      body = { token: payload.token };
    } else {
      // Legacy v1: send full proof data
      body = {
        proof:         payload.proof,
        publicInputs:  payload.publicInputs,
        nullifier:     payload.nullifier,
        timestamp:     payload.timestamp,
        ageRangeLabel: payload.ageRangeLabel,
      };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 45000);
    const res = await fetch(`${backendUrl}/verify`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const result = await res.json();

    const verifyTime = ((performance.now() - verifyStart) / 1000).toFixed(1);
    if (result.verified) {
      showVerifyResult(true, result.ageRangeLabel ?? payload.ageRangeLabel, payload.attestation ?? null, result.nullifier ?? null, verifyTime, result.disclosed ?? null);
    } else {
      showVerifyResult(false, result.reason ?? 'Verification failed', null, null, verifyTime, null);
    }
  } catch (err) {
    // Fallback: local proof verification (no nullifier check) - only for v1 payloads
    if (payload.version !== 2 && payload.proof) {
      try {
        const { verifyProofLocally } = await import('./zk.js');
        const valid = await verifyProofLocally({ proof: payload.proof, publicInputs: payload.publicInputs });
        showVerifyResult(valid, valid ? `${payload.ageRangeLabel} (local, no nullifier check)` : 'Invalid proof');
        return;
      } catch {
        // fall through to error
      }
    }
    setStatus('verify-status', `Backend error: ${err.message}`, 'error');
  }
}

async function showVerifyResult(ok, label, attestation, nullifier, verifyTime, disclosed) {
  const panel = $('verify-result');
  const icon  = $('result-icon');
  const text  = $('result-text');

  // Hide scan buttons and status while result is shown
  const scanBtns = $('verify-scan-btns');
  if (scanBtns) scanBtns.hidden = true;
  $('verify-status').hidden = true;

  panel.hidden       = false;
  icon.textContent   = ok ? '\u2713' : '\u2717';
  icon.className     = ok ? 'result-icon result-icon--ok' : 'result-icon result-icon--fail';
  text.textContent   = ok ? `Verified: ${label}` : `Failed: ${label}`;
  const timeNote = verifyTime ? ` (verified in ${verifyTime}s)` : '';
  $('attestation-status').textContent = '';

  if (ok) {
    let statusParts = [];
    if (attestation) {
      const valid = await verifyAttestation(attestation);
      statusParts.push(valid ? '\u2713 Legal attestation valid' : '\u26a0 Attestation signature invalid');
    }
    if (verifyTime) statusParts.push(`Verified in ${verifyTime}s`);
    $('attestation-status').textContent = statusParts.join(' \u00b7 ');
  }

  // Show disclosed fields
  const discEl = $('verify-disclosed');
  if (discEl) {
    if (ok && disclosed && Object.keys(disclosed).length > 0) {
      let html = '';
      if (disclosed.birthdate) html += `<div class="disclosed-field-row"><span class="disclosed-field-label">Birthdate</span><span class="disclosed-field-value">${MONTHS[disclosed.birthdate.month - 1]} ${disclosed.birthdate.day}, ${disclosed.birthdate.year}</span></div>`;
      if (disclosed.age != null) html += `<div class="disclosed-field-row"><span class="disclosed-field-label">Age</span><span class="disclosed-field-value">${disclosed.age}</span></div>`;
      if (disclosed.nationality) html += `<div class="disclosed-field-row"><span class="disclosed-field-label">Nationality</span><span class="disclosed-field-value">${disclosed.nationality}</span></div>`;
      if (disclosed.gender) html += `<div class="disclosed-field-row"><span class="disclosed-field-label">Gender</span><span class="disclosed-field-value">${disclosed.gender}</span></div>`;
      if (disclosed.name) html += `<div class="disclosed-field-row"><span class="disclosed-field-label">Name</span><span class="disclosed-field-value">${disclosed.name}</span></div>`;
      discEl.innerHTML = html;
      discEl.hidden = false;
    } else {
      discEl.hidden = true;
      discEl.innerHTML = '';
    }
  }

  // Show credential ID for successful verifications
  if (ok && nullifier) {
    const nullFp  = nullifier.slice(0, 10) + '...' + nullifier.slice(-8);
    const nullEl  = $('verify-nullifier');
    const copyBtn = $('verify-copy');
    const record  = $('verify-record');
    if (nullEl)  nullEl.textContent = nullFp;
    if (record)  record.hidden = false;
    if (copyBtn) {
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(nullifier)
          .then(() => { copyBtn.textContent = 'Copied!'; setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000); })
          .catch(() => { copyBtn.textContent = 'Error';  setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000); });
      };
    }
  }
}

function resetVerifyPanel() {
  $('verify-result').hidden = true;
  $('verify-status').hidden = true;
  const scanBtns = $('verify-scan-btns');
  if (scanBtns) scanBtns.hidden = false;
  const record = $('verify-record');
  if (record) record.hidden = true;
  const discEl = $('verify-disclosed');
  if (discEl) { discEl.hidden = true; discEl.innerHTML = ''; }
}

// ── Dark / light mode ─────────────────────────────────────────────────────────
function initTheme() {
  // The inline script in <head> already set the theme to avoid flash.
  // Here we just sync the toggle button icon to match.
  const current = document.documentElement.dataset.theme ?? 'light';
  const btn = $('themeToggle');
  if (btn) btn.textContent = current === 'dark' ? '\u2600' : '\ud83c\udf19';

  on('themeToggle', 'click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('theme', next);
    $('themeToggle').textContent = next === 'dark' ? '\u2600' : '\ud83c\udf19';
  });
}

// ── Nav ───────────────────────────────────────────────────────────────────────
function initNav() {
  on('createModeBtn',    'click', () => showMode('create'));
  on('verifyModeBtn',    'click', () => { stopCamera(); showMode('verify'); });
  on('faqModeBtn',       'click', () => { stopCamera(); showMode('faq'); });
  on('startOverBtn',     'click', startOver);
  on('startOverBtnShow', 'click', startOver);
  on('verifyAnotherBtn', 'click', resetVerifyPanel);
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initNav();
  initStep1();
  initStep2();
  initStep3();
  initVerifyMode();

  // If a backend URL is baked in at build time (e.g. ngrok URL), pre-fill it.
  const envBackend = import.meta.env.VITE_BACKEND_URL;
  if (envBackend) {
    const urlInput = $('backend-url-input');
    if (urlInput) urlInput.value = envBackend;
  }

  showMode('create');
  setStep(1);

  // Pre-warm the prover after a short delay so step 3 feels faster.
  setTimeout(() => initProver().catch(() => {}), 3000);
});

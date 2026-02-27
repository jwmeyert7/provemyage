// Web Crypto API: ECDSA attestation signing and credential storage (IndexedDB).
// The user's private key never leaves the device.
// The attestation binds: face_hash + age_range + timestamp + "I attest this is my passport"

const DB_NAME  = 'provemyage';
const DB_VER   = 1;
const KEY_STORE = 'attestation-keys';
const CRED_STORE = 'credentials';

// ── IndexedDB helpers ────────────────────────────────────────────────────────
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(KEY_STORE))  db.createObjectStore(KEY_STORE,  { keyPath: 'id' });
      if (!db.objectStoreNames.contains(CRED_STORE)) db.createObjectStore(CRED_STORE, { keyPath: 'id' });
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

async function idbGet(store, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

async function idbPut(store, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(store, 'readwrite');
    const req = tx.objectStore(store).put(value);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
  });
}

async function idbGetAll(store) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

// ── ECDSA key pair management ────────────────────────────────────────────────
const KEY_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGO = { name: 'ECDSA', hash: 'SHA-256' };

async function getOrCreateKeyPair() {
  const stored = await idbGet(KEY_STORE, 'main');
  if (stored) {
    const privateKey = await crypto.subtle.importKey('jwk', stored.privateJwk, KEY_ALGO, false, ['sign']);
    const publicKey  = await crypto.subtle.importKey('jwk', stored.publicJwk,  KEY_ALGO, true,  ['verify']);
    return { privateKey, publicKey, publicJwk: stored.publicJwk };
  }

  const pair = await crypto.subtle.generateKey(KEY_ALGO, true, ['sign', 'verify']);
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk  = await crypto.subtle.exportKey('jwk', pair.publicKey);
  await idbPut(KEY_STORE, { id: 'main', privateJwk, publicJwk });

  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk };
}

// ── Attestation signing ──────────────────────────────────────────────────────

/**
 * Create a signed legal attestation.
 * The message commits to: faceHash, ageRangeLabel, timestamp, and the legal declaration.
 *
 * @returns {Promise<{message, signature, publicKey}>}
 */
export async function createAttestation({ faceHash, ageRangeLabel, nullifierSeedHex }) {
  const { privateKey, publicJwk } = await getOrCreateKeyPair();

  const message = JSON.stringify({
    app:          'ProveMyAge v1',
    statement:    'I attest under penalty of perjury that this passport is genuinely mine, ' +
                  'I am the person in the selfie, and I understand misuse constitutes federal fraud.',
    faceHash,
    ageRangeLabel,
    nullifierRef: nullifierSeedHex.slice(2, 18), // partial reveal for binding, not the full seed
    issuedAt:     new Date().toISOString(),
  });

  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign(SIGN_ALGO, privateKey, enc.encode(message));

  return {
    message,
    signature:  btoa(String.fromCharCode(...new Uint8Array(sig))),
    publicKey:  publicJwk,
  };
}

/**
 * Verify an attestation signature (used by the verifier UI for display purposes).
 */
export async function verifyAttestation({ message, signature, publicKey }) {
  try {
    const pubKey = await crypto.subtle.importKey('jwk', publicKey, KEY_ALGO, false, ['verify']);
    const sigBuf = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    const enc    = new TextEncoder();
    return await crypto.subtle.verify(SIGN_ALGO, pubKey, sigBuf, enc.encode(message));
  } catch {
    return false;
  }
}

// ── Credential storage ───────────────────────────────────────────────────────

/**
 * Save a credential to IndexedDB.
 * A credential is: { proof, publicInputs, nullifierSeed, faceHash, ageRangeLabel, attestation, createdAt }
 */
export async function saveCredential(credential) {
  const id = crypto.randomUUID();
  await idbPut(CRED_STORE, { ...credential, id });
  return id;
}

export async function loadCredential(id) {
  return idbGet(CRED_STORE, id);
}

export async function listCredentials() {
  return idbGetAll(CRED_STORE);
}

// ── Random field element ─────────────────────────────────────────────────────
// Generate a random BN254 scalar field element for use as nullifier_seed.
export function randomFieldElement() {
  const bytes = crypto.getRandomValues(new Uint8Array(31)); // 248 bits < field modulus
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

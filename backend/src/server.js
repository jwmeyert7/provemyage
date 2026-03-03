import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { randomUUID } from 'crypto';
import { verifyProof } from './verifier.js';
import { spendNullifier } from './nullifier.js';
import { requireApiKey, createApiKey } from './auth.js';
import { dashboardRouter, recordEvent } from './dashboard.js';

// In-memory credential store - proof is too large for a QR code so the
// frontend POSTs it here and the QR just carries a short token.
// Credentials expire after 5 minutes.
const pendingCreds = new Map();
function storeCred(data) {
  const token = randomUUID();
  pendingCreds.set(token, data);
  setTimeout(() => pendingCreds.delete(token), 5 * 60 * 1000);
  return token;
}

const app  = express();
const PORT = process.env.PORT ?? 3001;

// ── Middleware ──────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.CORS_ORIGINS ?? 'http://localhost:5173')
  .split(',').map(s => s.trim());

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods: ['GET', 'POST'],
}));

app.use(express.json({ limit: '2mb' }));

// Global rate limit - 60 requests/minute per IP
app.use(rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false }));

// ── Routes ──────────────────────────────────────────────────────────────────

// Health check (no auth)
app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));

/**
 * POST /verify
 * Body: {
 *   proof:         number[]   - ZK proof bytes
 *   publicInputs:  string[]   - public inputs (hex strings, circuit output order)
 *   nullifier:     string     - nullifier hex (0x…) extracted from publicInputs
 *   timestamp:     number     - Unix seconds embedded in the proof
 *   ageRangeLabel: string     - human-readable label e.g. "18+"
 * }
 *
 * Returns: { verified: boolean, ageRangeLabel: string }
 * Never returns or logs any personal data.
 */
app.post('/verify', async (req, res) => {
  let body = req.body ?? {};

  // ── Token-based lookup (QR v2) ──────────────────────────────────────────
  if (body.token) {
    const stored = pendingCreds.get(body.token);
    if (!stored) {
      return res.status(400).json({ error: 'Token not found or expired' });
    }
    pendingCreds.delete(body.token); // single-use
    body = stored;
  }

  const { proof, publicInputs, nullifier, timestamp, ageRangeLabel, disclosed } = body;

  // ── Input validation ────────────────────────────────────────────────────
  if (!Array.isArray(proof) || !Array.isArray(publicInputs)) {
    return res.status(400).json({ error: 'proof and publicInputs must be arrays' });
  }
  if (typeof nullifier !== 'string' || !nullifier.startsWith('0x')) {
    return res.status(400).json({ error: 'nullifier must be a 0x hex string' });
  }
  if (typeof timestamp !== 'number') {
    return res.status(400).json({ error: 'timestamp must be a number' });
  }

  // ── Timestamp freshness check ───────────────────────────────────────────
  const TTL = Number(process.env.PROOF_TTL_SECONDS ?? 60);
  const age = Math.floor(Date.now() / 1000) - timestamp;
  if (age < 0 || age > TTL) {
    return res.status(400).json({ error: `Proof expired or future-dated (age=${age}s, max=${TTL}s)` });
  }

  // ── ZK proof verification ───────────────────────────────────────────────
  let isValid = false;
  try {
    isValid = await verifyProof({ proof, publicInputs });
  } catch (err) {
    console.error('[verify] proof verification threw:', err.message);
    return res.status(500).json({ error: 'Proof verification error' });
  }

  if (!isValid) {
    return res.status(200).json({ verified: false, reason: 'Invalid proof' });
  }

  // ── Nullifier: atomic check-and-spend ──────────────────────────────────
  const spent = !(await spendNullifier(nullifier));
  if (spent) {
    return res.status(200).json({ verified: false, reason: 'Nullifier already spent (credential reused)' });
  }

  // ── Record analytics event ──────────────────────────────────────────────
  await recordEvent(req.apiKeyMeta?.hash, { ageRangeLabel, verified: true, timestamp });

  res.json({ verified: true, ageRangeLabel: ageRangeLabel ?? 'Unknown', nullifier, disclosed: disclosed ?? null });
});

// ── Credential store (short token → proof data for QR size reduction) ────────
/**
 * POST /credentials
 * Body: { proof, publicInputs, nullifier, timestamp, ageRangeLabel }
 * Returns: { token } - a UUID the QR code carries instead of the full proof
 * No API key required; rate-limited by global limiter.
 */
app.post('/credentials', async (req, res) => {
  const { proof, publicInputs, nullifier, timestamp, ageRangeLabel, disclosed } = req.body ?? {};
  if (!Array.isArray(proof) || !Array.isArray(publicInputs)) {
    return res.status(400).json({ error: 'proof and publicInputs must be arrays' });
  }
  if (typeof nullifier !== 'string' || !nullifier.startsWith('0x')) {
    return res.status(400).json({ error: 'nullifier must be a 0x hex string' });
  }
  if (typeof timestamp !== 'number') {
    return res.status(400).json({ error: 'timestamp must be a number' });
  }
  const token = storeCred({ proof, publicInputs, nullifier, timestamp, ageRangeLabel, disclosed: disclosed ?? null });
  res.json({ token, expiresIn: 5 * 60 });
});

// ── Verifier dashboard ──────────────────────────────────────────────────────
app.use('/dashboard', dashboardRouter);

// ── API key provisioning (admin-only in prod; open here for local dev) ──────
app.post('/admin/keys', async (req, res) => {
  const { email, tier } = req.body ?? {};
  if (!email) return res.status(400).json({ error: 'email required' });
  try {
    const result = await createApiKey({ email, tier });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[provemyage-backend] listening on http://localhost:${PORT}`);
});

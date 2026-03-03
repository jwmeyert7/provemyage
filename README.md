# ProveMyAge

Zero-knowledge age verification from a real passport. Proves you meet an age threshold (18+, 21+, custom range) without revealing your name, birthdate, or any personal data.

## How It Works

1. **Passport OCR** - Tesseract.js WASM reads the MRZ (machine-readable zone) locally. No photo ever leaves the browser.
2. **Selfie binding** - MediaPipe FaceMesh computes a normalized face embedding hash. Photo immediately discarded.
3. **Legal attestation** - ECDSA-signed declaration using Web Crypto API. Key lives in browser IndexedDB.
4. **ZK proof** - Noir circuit (Barretenberg) proves birth date satisfies the age threshold without revealing it.
5. **QR credential** - 60-second single-use QR; backend checks proof validity + Redis nullifier (anti-replay).

## Trust Model

| Layer | Mechanism |
|-------|-----------|
| Real document | ICAO 9303 MRZ check digits (5 independent checksums) |
| Identity binding | MediaPipe face hash committed in the ZK proof |
| Legal accountability | ECDSA-signed attestation - misuse is federal fraud |
| Anti-replay | Single-use nullifier stored in Redis with 7-day retention |

Verify claims in DevTools → Network tab: zero requests during passport processing.

## Tech Stack

| Component | Tech |
|-----------|------|
| Frontend | Vite + vanilla JS |
| OCR | Tesseract.js 5 (WASM) |
| ZK proving | Noir 0.36 + Barretenberg (`@noir-lang/backend_barretenberg`) |
| Face detection | MediaPipe FaceMesh |
| QR | qrcode + jsQR |
| Backend | Node.js + Express |
| Nullifier store | Redis (ioredis) |

## Quick Start

### Prerequisites
- Node.js ≥ 18
- Redis running locally (`redis-server`) - or set `REDIS_URL` in backend `.env`

### 1. Compile the Noir Circuit

```bash
cd scripts
npm install
node compile-circuit.js
# → circuits/age_proof/target/age_proof.json
```

Copy the artifact to the frontend's public directory:
```bash
mkdir -p frontend/public/circuits
cp circuits/age_proof/target/age_proof.json frontend/public/circuits/age_proof.json
```

### 2. Backend

```bash
cd backend
npm install
cp .env.example .env
# Edit .env as needed
npm run dev
# → http://localhost:3001
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

Open http://localhost:5173. The COEP/COOP headers Vite sets are required for Barretenberg SharedArrayBuffer.

### 4. Get a Verifier API Key (local dev)

```bash
curl -X POST http://localhost:3001/admin/keys \
 -H 'Content-Type: application/json' \
 -d '{"email":"you@example.com","tier":"free"}'
```

Paste the returned `apiKey` into the Verify tab of the app.

## Adding a New Network / Age Threshold

Age thresholds are computed client-side in `frontend/src/main.js` (`AGE_PRESETS`). Add a new entry to the array.

## Circuit Details

**File:** `circuits/age_proof/src/main.nr`

| Input | Visibility | Purpose |
|-------|-----------|---------|
| `birth_year/month/day` | Private | Actual birthdate from passport MRZ |
| `nullifier_seed` | Private | Random scalar; makes nullifier unguessable |
| `threshold_year/month/day` | Public | Today - min age (proves age ≥ min) |
| `face_hash` | Public | Binds selfie to this proof |
| `current_timestamp` | Public | For 60-second expiry |
| `has_upper_bound`, `upper_*` | Public | Optional maximum age (e.g. Under 18) |
| return `Field` | Public output | Nullifier = pedersen(seed, timestamp, face_hash) |

## Backend Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET  /health` | None | Liveness check |
| `POST /verify` | Bearer API key | Verify ZK proof + spend nullifier |
| `GET  /dashboard/stats` | Bearer API key | Current-month usage |
| `GET  /dashboard/history` | Bearer API key | Last 30 verification events |
| `POST /admin/keys` | None (secure in prod) | Create verifier API key |

## Verifier Tiers

| Tier | Price | Verifications/month |
|------|-------|---------------------|
| Free | $0 | 100 |
| Pro | contact us | Unlimited |

## Deployment

- **Frontend**: any static host (Netlify, Vercel, S3). Must set COOP/COEP headers.
- **Backend**: any Node.js host (Railway, Fly, Render). Requires Redis.
- For offline frontend use, serve MediaPipe WASM assets locally (see `frontend/src/face.js`).

## License

MIT

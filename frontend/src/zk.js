// ZK proof generation using Noir + Barretenberg WASM.
// All computation is local - the private birth date never leaves the browser.
//
// The circuit artifact (compiled ACIR JSON) must be present at:
//   /circuits/age_proof.json   (served as a static asset from public/)
//
// Thread count: defaults to navigator.hardwareConcurrency for max speed.

// Do NOT import these at the top level - @aztec/bb.js contains a top-level
// await that blocks the entire module graph for 30+ seconds on page load,
// making every button in the app appear dead. Load lazily inside initProver.
let noir    = null;
let backend = null;

export async function initProver(onStatus) {
  if (noir) return;
  if (onStatus) onStatus('Loading ZK circuit…');

  // Lazy-load the heavy WASM packages only when actually needed
  const [{ Noir }, { BarretenbergBackend }] = await Promise.all([
    import('@noir-lang/noir_js'),
    import('@noir-lang/backend_barretenberg'),
  ]);

  let artifact;
  try {
    const res = await fetch('/circuits/age_proof.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    artifact = await res.json();
  } catch (err) {
    throw new Error(
      `Could not load circuit artifact (/circuits/age_proof.json). ` +
      `Run the compile script first: cd scripts && npm i && node compile-circuit.js. ` +
      `Original error: ${err.message}`
    );
  }

  if (onStatus) onStatus('Initializing Barretenberg prover…');

  const threads = Math.max(1, (navigator.hardwareConcurrency ?? 4) - 1);
  backend = new BarretenbergBackend(artifact, { threads });
  // In @noir-lang/noir_js@0.36.0 Noir takes only the artifact; backend is used separately
  noir = new Noir(artifact);

  if (onStatus) onStatus('Prover ready');
}

// ── Helpers for encoding selective disclosure fields ─────────────────────────

/** Pack a 3-letter nationality code (e.g. "USA") into a u32: c1*65536 + c2*256 + c3 */
export function packNationality(code) {
  if (!code || code.length === 0) return 0;
  const c = code.toUpperCase().padEnd(3, '<');
  return c.charCodeAt(0) * 65536 + c.charCodeAt(1) * 256 + c.charCodeAt(2);
}

/** Unpack a u32 nationality code back to a 3-letter string */
export function unpackNationality(n) {
  if (!n) return '';
  const c1 = String.fromCharCode((n >> 16) & 0xFF);
  const c2 = String.fromCharCode((n >> 8) & 0xFF);
  const c3 = String.fromCharCode(n & 0xFF);
  return (c1 + c2 + c3).replace(/</g, '').trim();
}

/** Encode gender to u32: 'M'=77, 'F'=70, null/other=0 */
export function packGender(g) {
  if (g === 'M') return 77;
  if (g === 'F') return 70;
  return 0;
}

/** Decode gender from u32 */
export function unpackGender(n) {
  if (n === 77) return 'M';
  if (n === 70) return 'F';
  return null;
}

/**
 * Pack a name string (up to 31 chars) into a hex Field string.
 * Each character becomes one byte, big-endian packed.
 */
export function packNameToField(name) {
  if (!name || name.length === 0) return '0x00';
  const bytes = new TextEncoder().encode(name.slice(0, 31));
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Unpack a hex Field string back to a name string.
 * Strips trailing null bytes.
 */
export function unpackFieldToName(hex) {
  if (!hex || hex === '0x00' || hex === '0x0' || hex === '0x') return '';
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) {
    const b = parseInt(clean.slice(i, i + 2), 16);
    if (b === 0) break;
    bytes.push(b);
  }
  return new TextDecoder().decode(Uint8Array.from(bytes));
}

/**
 * Generate a ZK age proof with optional selective disclosure.
 * Private inputs (birth date, name, nationality, gender) are never exposed
 * unless the corresponding reveal flag is true.
 *
 * @param {Object} p
 * @param {number}  p.birthYear
 * @param {number}  p.birthMonth
 * @param {number}  p.birthDay
 * @param {string}  p.nullifierSeed    - 0x hex Field element (private)
 * @param {number}  p.thresholdYear    - "today minus minAge" year
 * @param {number}  p.thresholdMonth
 * @param {number}  p.thresholdDay
 * @param {string}  p.faceHash         - 0x hex Field element (public)
 * @param {number}  p.currentTimestamp - Unix seconds (public)
 * @param {boolean} [p.hasUpperBound]
 * @param {number}  [p.upperYear]
 * @param {number}  [p.upperMonth]
 * @param {number}  [p.upperDay]
 * @param {number}  [p.nationalityCode] - packed u32 (private)
 * @param {number}  [p.genderCode]     - packed u32 (private)
 * @param {string}  [p.namePart1]      - 0x hex Field (private)
 * @param {string}  [p.namePart2]      - 0x hex Field (private)
 * @param {number}  [p.refYear]        - today's year (public, for age calc)
 * @param {number}  [p.refMonth]       - today's month
 * @param {number}  [p.refDay]         - today's day
 * @param {boolean} [p.revealBirthdate]
 * @param {boolean} [p.revealAge]
 * @param {boolean} [p.revealNationality]
 * @param {boolean} [p.revealGender]
 * @param {boolean} [p.revealName]
 * @param {Function} [p.onStatus]
 * @returns {Promise<{proof: number[], publicInputs: string[], nullifier: string, disclosed: Object}>}
 */
export async function generateAgeProof({
  birthYear, birthMonth, birthDay,
  nullifierSeed,
  thresholdYear, thresholdMonth, thresholdDay,
  faceHash,
  currentTimestamp,
  hasUpperBound = false,
  upperYear = 0, upperMonth = 0, upperDay = 0,
  nationalityCode = 0,
  genderCode = 0,
  namePart1 = '0x00',
  namePart2 = '0x00',
  refYear = 0, refMonth = 0, refDay = 0,
  revealBirthdate = false,
  revealAge = false,
  revealNationality = false,
  revealGender = false,
  revealName = false,
  onStatus,
}) {
  await initProver(onStatus);

  if (onStatus) onStatus('Generating witness…');

  // Fill in reference date if not provided (today's date)
  if (!refYear) {
    const d = new Date();
    refYear  = d.getUTCFullYear();
    refMonth = d.getUTCMonth() + 1;
    refDay   = d.getUTCDate();
  }

  // @noir-lang/noir_js@0.36.0 expects all numeric values as strings
  const inputs = {
    birth_year:        String(birthYear),
    birth_month:       String(birthMonth),
    birth_day:         String(birthDay),
    nullifier_seed:    nullifierSeed,
    nationality_code:  String(nationalityCode),
    gender_code:       String(genderCode),
    name_part1:        namePart1,
    name_part2:        namePart2,
    threshold_year:    String(thresholdYear),
    threshold_month:   String(thresholdMonth),
    threshold_day:     String(thresholdDay),
    face_hash:         faceHash,
    current_timestamp: String(currentTimestamp),
    has_upper_bound:   hasUpperBound,
    upper_year:        String(upperYear),
    upper_month:       String(upperMonth),
    upper_day:         String(upperDay),
    ref_year:          String(refYear),
    ref_month:         String(refMonth),
    ref_day:           String(refDay),
    reveal_birthdate:    revealBirthdate,
    reveal_age:          revealAge,
    reveal_nationality:  revealNationality,
    reveal_gender:       revealGender,
    reveal_name:         revealName,
  };

  let witness, returnValues;
  try {
    const result = await noir.execute(inputs);
    witness = result.witness;

    // noir_js may return [Field; 9] as a flat array or nested - normalize
    let rv = result.returnValue;
    console.log('[zk] raw returnValue:', JSON.stringify(rv));
    if (rv && !Array.isArray(rv)) rv = [rv];
    else if (rv && rv.length === 1 && Array.isArray(rv[0])) rv = rv[0];
    returnValues = rv;
    console.log('[zk] parsed returnValues:', returnValues?.length, 'elements');
  } catch (err) {
    throw new Error(`Witness generation failed: ${err.message}`);
  }

  if (onStatus) onStatus('Proving... (this takes 30-60 seconds)');

  let proof, publicInputs;
  try {
    ({ proof, publicInputs } = await backend.generateProof(witness));
    console.log('[zk] publicInputs:', publicInputs.length, 'elements');
  } catch (err) {
    throw new Error(`Proof generation failed: ${err.message}`);
  }

  // The 9 return values (public outputs) appear at the start of publicInputs
  // in Barretenberg. Use them as primary source, with returnValues as fallback.
  const rv = returnValues && returnValues.length === 9 ? returnValues : publicInputs.slice(0, 9);
  console.log('[zk] using rv source:', returnValues?.length === 9 ? 'returnValues' : 'publicInputs[0:9]');

  const nullifier = rv[0];

  // Extract disclosed fields from return values
  const disclosed = {};
  try {
    if (revealBirthdate) {
      const y = Number(BigInt(rv[1]));
      const m = Number(BigInt(rv[2]));
      const d = Number(BigInt(rv[3]));
      if (y > 0) disclosed.birthdate = { year: y, month: m, day: d };
    }
    if (revealAge) {
      const a = Number(BigInt(rv[4]));
      if (a > 0) disclosed.age = a;
    }
    if (revealNationality) {
      const n = Number(BigInt(rv[5]));
      if (n > 0) disclosed.nationality = unpackNationality(n);
    }
    if (revealGender) {
      const g = Number(BigInt(rv[6]));
      if (g > 0) disclosed.gender = unpackGender(g);
    }
    if (revealName) {
      const n1 = unpackFieldToName(rv[7]);
      const n2 = unpackFieldToName(rv[8]);
      const fullName = (n1 + n2).replace(/<<+/g, ', ').replace(/<+/g, ' ').trim();
      if (fullName) disclosed.name = fullName;
    }
  } catch (err) {
    console.warn('[zk] disclosed field extraction error:', err.message);
  }
  console.log('[zk] disclosed:', JSON.stringify(disclosed));

  if (onStatus) onStatus('Proof complete ✓');

  return {
    proof:        Array.from(proof),
    publicInputs,
    nullifier,
    disclosed,
  };
}

/**
 * Verify a proof locally (optional - backend always re-verifies).
 */
export async function verifyProofLocally({ proof, publicInputs }) {
  await initProver();
  return backend.verifyProof({ proof: Uint8Array.from(proof), publicInputs });
}

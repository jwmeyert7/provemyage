// ZK proof generation using Noir + Barretenberg WASM.
// All computation is local — the private birth date never leaves the browser.
//
// The circuit artifact (compiled ACIR JSON) must be present at:
//   /circuits/age_proof.json   (served as a static asset from public/)
//
// Thread count: defaults to navigator.hardwareConcurrency for max speed.

// Do NOT import these at the top level — @aztec/bb.js contains a top-level
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

/**
 * Generate a ZK age proof.
 * Private inputs (birth date) are never exposed in the output.
 *
 * @param {Object} p
 * @param {number}  p.birthYear
 * @param {number}  p.birthMonth
 * @param {number}  p.birthDay
 * @param {string}  p.nullifierSeed     - 0x hex Field element (private)
 * @param {number}  p.thresholdYear     - "today minus minAge" year
 * @param {number}  p.thresholdMonth
 * @param {number}  p.thresholdDay
 * @param {string}  p.faceHash          - 0x hex Field element (public)
 * @param {number}  p.currentTimestamp  - Unix seconds (public)
 * @param {boolean} [p.hasUpperBound]
 * @param {number}  [p.upperYear]
 * @param {number}  [p.upperMonth]
 * @param {number}  [p.upperDay]
 * @param {Function} [p.onStatus]
 * @returns {Promise<{proof: number[], publicInputs: string[], nullifier: string}>}
 */
export async function generateAgeProof({
  birthYear, birthMonth, birthDay,
  nullifierSeed,
  thresholdYear, thresholdMonth, thresholdDay,
  faceHash,
  currentTimestamp,
  hasUpperBound = false,
  upperYear = 0, upperMonth = 0, upperDay = 0,
  onStatus,
}) {
  await initProver(onStatus);

  if (onStatus) onStatus('Generating witness…');

  // @noir-lang/noir_js@0.36.0 expects all numeric values as strings
  const inputs = {
    birth_year:        String(birthYear),
    birth_month:       String(birthMonth),
    birth_day:         String(birthDay),
    nullifier_seed:    nullifierSeed,        // Field — already a 0x hex string
    threshold_year:    String(thresholdYear),
    threshold_month:   String(thresholdMonth),
    threshold_day:     String(thresholdDay),
    face_hash:         faceHash,             // Field — already a 0x hex string
    current_timestamp: String(currentTimestamp), // u64 as string
    has_upper_bound:   hasUpperBound,        // bool — native JS boolean
    upper_year:        String(upperYear),
    upper_month:       String(upperMonth),
    upper_day:         String(upperDay),
  };

  let witness, nullifierFromReturn;
  try {
    const result = await noir.execute(inputs);
    witness = result.witness;
    nullifierFromReturn = result.returnValue; // The circuit's return value IS the nullifier
  } catch (err) {
    throw new Error(`Witness generation failed: ${err.message}`);
  }

  if (onStatus) onStatus('Proving… (this takes 30–60 seconds)');

  let proof, publicInputs;
  try {
    ({ proof, publicInputs } = await backend.generateProof(witness));
  } catch (err) {
    throw new Error(`Proof generation failed: ${err.message}`);
  }

  // The nullifier is the circuit's return value (computed during witness generation)
  const nullifier = nullifierFromReturn ?? publicInputs[publicInputs.length - 1];

  if (onStatus) onStatus('Proof complete ✓');

  return {
    proof:        Array.from(proof),
    publicInputs,
    nullifier,    // 0x hex string — used by backend to prevent replay
  };
}

/**
 * Verify a proof locally (optional — backend always re-verifies).
 */
export async function verifyProofLocally({ proof, publicInputs }) {
  await initProver();
  return backend.verifyProof({ proof: Uint8Array.from(proof), publicInputs });
}

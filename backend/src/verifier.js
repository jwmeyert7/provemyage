// Barretenberg proof verifier for the age_proof Noir circuit.
// Loads the compiled circuit artifact once and reuses the backend instance.

import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let backend = null;
let noir    = null;

async function init() {
  if (backend) return;

  const artifactPath = join(__dirname, '../circuits/age_proof.json');
  let artifact;
  try {
    artifact = JSON.parse(readFileSync(artifactPath, 'utf-8'));
  } catch {
    throw new Error(
      `Circuit artifact not found at ${artifactPath}. ` +
      'Run: cd scripts && npm install && node compile-circuit.js'
    );
  }

  backend = new BarretenbergBackend(artifact);
  noir    = new Noir(artifact, backend);
  console.log('[verifier] Barretenberg backend initialized');
}

/**
 * Verify a ZK proof.
 * @param {Object} params
 * @param {number[]} params.proof        - Proof bytes as number array
 * @param {string[]} params.publicInputs - Public inputs array (hex strings)
 * @returns {Promise<boolean>}
 */
export async function verifyProof({ proof, publicInputs }) {
  await init();

  try {
    const proofBytes = Uint8Array.from(proof);
    const isValid = await backend.verifyProof({ proof: proofBytes, publicInputs });
    return isValid;
  } catch (err) {
    console.error('[verifier] verifyProof error:', err.message);
    return false;
  }
}

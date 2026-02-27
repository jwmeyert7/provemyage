#!/usr/bin/env node
// End-to-end proof generation + verification test.
// Verifies that the Barretenberg backend can prove and verify a valid age claim.
// Run: node test-proof.js

import { Noir } from '@noir-lang/noir_js';
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const artifactPath = join(__dirname, '../circuits/age_proof/target/age_proof.json');

async function main() {
  console.log('Loading circuit artifact…');
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf-8'));
  console.log(`Noir version: ${artifact.noir_version}`);
  console.log(`ABI parameters: ${artifact.abi.parameters.length}`);

  console.log('\nInitializing Barretenberg backend…');
  const backend = new BarretenbergBackend(artifact, { threads: 4 });
  // In @noir-lang/noir_js@0.36.0, Noir takes only the artifact (no backend)
  const noir = new Noir(artifact);

  // Test case: person born 1990-05-15, proving they are 18+ as of today
  // Threshold = today - 18 years
  const today = new Date();
  const threshold = new Date(today);
  threshold.setFullYear(threshold.getFullYear() - 18);

  // All numeric inputs are passed as strings in @noir-lang/noir_js@0.36.0
  const inputs = {
    // Private — would come from passport MRZ in real use
    birth_year:   '1990',
    birth_month:  '5',
    birth_day:    '15',
    nullifier_seed: '0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',

    // Public — minimum age threshold (today − 18 years)
    threshold_year:  String(threshold.getUTCFullYear()),
    threshold_month: String(threshold.getUTCMonth() + 1),
    threshold_day:   String(threshold.getUTCDate()),

    // Public — face hash (normally computed from MediaPipe landmarks)
    face_hash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd',

    // Public — Unix timestamp (seconds) as string
    current_timestamp: String(Math.floor(Date.now() / 1000)),

    // No upper bound for this test
    has_upper_bound: false,
    upper_year:  '0',
    upper_month: '0',
    upper_day:   '0',
  };

  console.log(`\nProving: born ${inputs.birth_year}-${inputs.birth_month}-${inputs.birth_day}`);
  console.log(`Threshold (18+ today): ${inputs.threshold_year}-${inputs.threshold_month}-${inputs.threshold_day}`);
  console.log('\nGenerating witness…');

  let witness;
  try {
    const { witness: w, returnValue } = await noir.execute(inputs);
    witness = w;
    console.log('Witness generated ✓');
    console.log('Return value (nullifier):', returnValue);
  } catch (err) {
    console.error('Witness generation FAILED:', err.message);
    process.exit(1);
  }

  console.log('\nGenerating proof (this may take 30–90 seconds)…');
  const t0 = Date.now();

  let proof, publicInputs;
  try {
    ({ proof, publicInputs } = await backend.generateProof(witness));
    console.log(`Proof generated ✓ in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    console.log(`Proof size: ${proof.length} bytes`);
    console.log(`Public inputs (${publicInputs.length}):`, publicInputs);
  } catch (err) {
    console.error('Proof generation FAILED:', err.message);
    process.exit(1);
  }

  console.log('\nVerifying proof…');
  let isValid;
  try {
    isValid = await backend.verifyProof({ proof, publicInputs });
    console.log(`Verification result: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
  } catch (err) {
    console.error('Verification FAILED:', err.message);
    process.exit(1);
  }

  if (!isValid) {
    console.error('Proof is invalid — something went wrong.');
    process.exit(1);
  }

  // Test that an underage person cannot prove 18+
  console.log('\nTesting rejection: underage person trying to prove 18+…');
  const underageInputs = {
    ...inputs,
    birth_year:  '2010',  // 14 years old
    birth_month: '1',
    birth_day:   '1',
  };

  let rejectedCorrectly = false;
  const noirUnderage = new Noir(artifact);
  try {
    await noirUnderage.execute(underageInputs);
    console.error('ERROR: Should have rejected underage person!');
  } catch {
    rejectedCorrectly = true;
    console.log('Underage claim correctly rejected ✓');
  }

  if (rejectedCorrectly) {
    console.log('\n✅ All tests passed! ZK stack is working end-to-end.');
  }

  process.exit(0);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});

#!/usr/bin/env node
// Compiles the Noir age_proof circuit to a JSON artifact using @noir-lang/noir_wasm.
// Output: circuits/age_proof/target/age_proof.json
// This file is then imported by both the frontend (prover) and backend (verifier).
//
// Uses the low-level compile_program API to avoid Windows path-separator issues
// in the high-level wrapper.

import { compile_program, PathToFileSourceMap } from '@noir-lang/noir_wasm';
import { readFileSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const circuitDir = join(root, 'circuits', 'age_proof');

async function main() {
  console.log('📦 Compiling Noir circuit age_proof …');

  const src = readFileSync(join(circuitDir, 'src', 'main.nr'), 'utf-8');

  // Use POSIX-style virtual paths for the WASM compiler (avoids Windows backslash issues)
  const entryPoint = '/src/main.nr';
  const sourceMap = new PathToFileSourceMap();
  sourceMap.add_source_code(entryPoint, src);

  console.log('  Entry point:', entryPoint);
  console.log('  Source length:', src.length, 'chars');

  let result;
  try {
    result = await compile_program(entryPoint, undefined, sourceMap);
  } catch (err) {
    console.error('❌ Compilation failed:\n', err.message ?? err);
    if (err.diagnostics) {
      for (const d of err.diagnostics) {
        console.error('  ', d.message);
      }
    }
    process.exit(1);
  }

  const artifact = result.program ?? result;

  const outDir = join(circuitDir, 'target');
  mkdirSync(outDir, { recursive: true });
  const outPath = join(outDir, 'age_proof.json');
  writeFileSync(outPath, JSON.stringify(artifact, null, 2));

  console.log(`✅ Artifact written to ${outPath}`);
  console.log(`   bytecode present: ${!!artifact.bytecode}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

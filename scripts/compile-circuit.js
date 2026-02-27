#!/usr/bin/env node
// Compiles the Noir age_proof circuit to a JSON artifact using @noir-lang/noir_wasm.
// Output: circuits/age_proof/target/age_proof.json
// This file is then imported by both the frontend (prover) and backend (verifier).

import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { readFileSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

async function main() {
  console.log('📦 Compiling Noir circuit age_proof …');

  const fm = createFileManager('/');

  // Feed Nargo.toml and source file into the in-memory file manager
  const toml = readFileSync(join(root, 'circuits/age_proof/Nargo.toml'), 'utf-8');
  const src  = readFileSync(join(root, 'circuits/age_proof/src/main.nr'), 'utf-8');

  fm.writeFile('/Nargo.toml', toml);
  fm.writeFile('/src/main.nr', src);

  let result;
  try {
    result = await compile(fm);
  } catch (err) {
    console.error('❌ Compilation failed:\n', err.message ?? err);
    process.exit(1);
  }

  // noir_wasm 0.36 returns { program: CompiledProgram, ... }
  const artifact = result.program ?? result;

  const outDir = join(root, 'circuits/age_proof/target');
  mkdirSync(outDir, { recursive: true });
  const outPath = join(outDir, 'age_proof.json');
  writeFileSync(outPath, JSON.stringify(artifact, null, 2));

  console.log(`✅ Artifact written to ${outPath}`);
  console.log(`   ACIR opcodes: ${artifact.bytecode ? '(bytecode present)' : '(check artifact shape)'}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

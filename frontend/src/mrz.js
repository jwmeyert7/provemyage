// MRZ (Machine Readable Zone) extraction from passport images.
// Uses Tesseract.js WASM — all processing is local, zero network requests.
// Implements ICAO 9303 TD3 (standard passport) check-digit validation.

import { createWorker } from 'tesseract.js';

// ── ICAO 9303 check-digit algorithm ─────────────────────────────────────────
const CHAR_VALUES = Object.fromEntries([
  ...Array.from({ length: 10 }, (_, i) => [String(i), i]),
  ...Array.from({ length: 26 }, (_, i) => [String.fromCharCode(65 + i), 10 + i]),
  ['<', 0],
]);

function checkDigit(field) {
  const weights = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < field.length; i++) {
    sum += (CHAR_VALUES[field[i]] ?? 0) * weights[i % 3];
  }
  return sum % 10;
}

function validateCD(field, digit) {
  return checkDigit(field) === parseInt(digit, 10);
}

// ── TD3 line-2 parser ────────────────────────────────────────────────────────
// Line 2 format (44 chars):
//  [0-8]  Document number  [9] check  [10-12] Nationality
//  [13-18] Birth YYMMDD   [19] check  [20] Sex
//  [21-26] Expiry YYMMDD  [27] check  [28-41] Optional  [42] check  [43] composite check
function parseLine2(line) {
  if (line.length !== 44) throw new Error(`Line2 length ${line.length} ≠ 44`);

  const docNum   = line.slice(0, 9);
  const docCheck = line[9];
  const birth    = line.slice(13, 19);
  const bCheck   = line[19];
  const expiry   = line.slice(21, 27);
  const eCheck   = line[27];
  const optional = line.slice(28, 42);
  const oCheck   = line[42];
  const composite = line.slice(0, 10) + line.slice(13, 20) + line.slice(21, 43);
  const cCheck   = line[43];

  if (!validateCD(docNum, docCheck))    throw new Error('Document number check digit invalid');
  if (!validateCD(birth, bCheck))       throw new Error('Birth date check digit invalid');
  if (!validateCD(expiry, eCheck))      throw new Error('Expiry date check digit invalid');
  if (!validateCD(optional, oCheck))    throw new Error('Optional field check digit invalid');
  if (!validateCD(composite, cCheck))   throw new Error('Composite check digit invalid');

  // Parse 2-digit birth year → 4-digit
  const yy = parseInt(birth.slice(0, 2), 10);
  const mm = parseInt(birth.slice(2, 4), 10);
  const dd = parseInt(birth.slice(4, 6), 10);
  const currentYear = new Date().getUTCFullYear();
  // Persons born in future 2-digit years are impossible; assume 19xx if yy > (current - 2000 + 1)
  const yyyy = yy > (currentYear - 2000 + 1) ? 1900 + yy : 2000 + yy;

  return { birthYear: yyyy, birthMonth: mm, birthDay: dd,
           nationality: line.slice(10, 13).replace(/</g, ''),
           documentNumber: docNum.replace(/</g, '') };
}

// ── OCR cleanup helpers ──────────────────────────────────────────────────────
function normalizeLine(raw) {
  return raw.toUpperCase().replace(/[^A-Z0-9<]/g, '').padEnd(44, '<').slice(0, 44);
}

function extractMRZ(ocrText) {
  // MRZ lines are densely packed uppercase text — filter plausible lines
  const candidates = ocrText
    .split('\n')
    .map(l => l.replace(/\s/g, '').toUpperCase())
    .filter(l => l.length >= 38);

  for (let i = 0; i < candidates.length - 1; i++) {
    const l1 = normalizeLine(candidates[i]);
    const l2 = normalizeLine(candidates[i + 1]);
    // TD3 line 1 starts with 'P' (passport) or 'V' (visa)
    if (l1[0] !== 'P' && l1[0] !== 'V') continue;
    try {
      return { line1: l1, line2: l2, parsed: parseLine2(l2) };
    } catch {
      continue;
    }
  }
  throw new Error('No valid MRZ found. Try a clearer passport photo — the text zone at the bottom.');
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Extract birth date from a passport image file.
 * Everything runs locally in WebAssembly — no network requests.
 *
 * @param {File|Blob|string} imageSource - image file or data URL
 * @param {Function} [onProgress]        - progress callback (0–100)
 * @returns {Promise<{birthYear, birthMonth, birthDay, nationality}>}
 */
export async function extractBirthDateFromPassport(imageSource, onProgress) {
  // In Tesseract.js v5 the third argument is WorkerOptions (logger, langPath, etc.).
  // Engine parameters must be set via worker.setParameters() after creation.
  const worker = await createWorker('eng', 1, {
    logger: m => {
      if (onProgress && typeof m.progress === 'number') {
        onProgress(Math.round(m.progress * 80));
      }
    },
  });

  try {
    // Restrict OCR charset to valid MRZ characters for much better accuracy
    await worker.setParameters({
      tessedit_char_whitelist: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<',
      tessedit_pageseg_mode: '6',  // Uniform block of text
      load_system_dawg: '0',
      load_freq_dawg: '0',
    });

    const result = await worker.recognize(imageSource, {}, { text: true });

    if (onProgress) onProgress(90);

    const { parsed } = extractMRZ(result.data.text);
    return parsed;
  } finally {
    await worker.terminate();
  }
}

/**
 * Calculate the threshold date for a given minimum age.
 * The threshold is "today minus minAge years". If a person was born on or
 * before this date, they are at least minAge years old.
 */
export function thresholdDateForAge(minAge) {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() - minAge);
  return { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1, day: d.getUTCDate() };
}

/**
 * Calculate the upper-bound threshold for a maximum age.
 * Born on or after this date means the person is at most maxAge years old.
 */
export function upperBoundDateForAge(maxAge) {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() - maxAge - 1);
  d.setUTCDate(d.getUTCDate() + 1); // exclusive upper: born strictly after this date
  return { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1, day: d.getUTCDate() };
}

// API key management for verifiers.
// Free tier: 100 verifications/month.
// Paid tier: unlimited (billed externally).
//
// API keys are stored in Redis as hashes: apikey:{sha256(key)} → { tier, email, … }
// Monthly usage counters: usage:{sha256(key)}:{YYYY-MM} → count

import { createHash } from 'crypto';
import { getRedis } from './nullifier.js';
import { v4 as uuidv4 } from 'uuid';

const FREE_MONTHLY_LIMIT = 100;
const MONTHLY_TTL = 35 * 24 * 60 * 60; // 35 days in seconds

function hashKey(apiKey) {
  return createHash('sha256').update(apiKey).digest('hex');
}

function monthKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

/**
 * Create a new API key for a verifier.
 * Returns the raw key (shown once) and its metadata.
 */
export async function createApiKey({ email, tier = 'free' }) {
  const rawKey = `pma_${uuidv4().replace(/-/g, '')}`;
  const hash   = hashKey(rawKey);
  const redis  = getRedis();

  await redis.hset(`apikey:${hash}`, {
    tier,
    email,
    createdAt: new Date().toISOString(),
    active: '1',
  });

  return { apiKey: rawKey, hash, tier, email };
}

/**
 * Middleware: validate API key from Authorization header.
 * Attaches req.apiKeyMeta = { hash, tier, email } on success.
 */
export async function requireApiKey(req, res, next) {
  const header = req.headers['authorization'] ?? '';
  const rawKey = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!rawKey) {
    return res.status(401).json({ error: 'Missing Authorization: Bearer <api_key>' });
  }

  const hash  = hashKey(rawKey);
  const redis = getRedis();
  const meta  = await redis.hgetall(`apikey:${hash}`);

  if (!meta || meta.active !== '1') {
    return res.status(403).json({ error: 'Invalid or revoked API key' });
  }

  // Check monthly quota for free tier
  if (meta.tier === 'free') {
    const usageKey = `usage:${hash}:${monthKey()}`;
    const count    = await redis.incr(usageKey);
    if (count === 1) await redis.expire(usageKey, MONTHLY_TTL);

    if (count > FREE_MONTHLY_LIMIT) {
      return res.status(429).json({
        error: 'Free tier monthly limit reached',
        limit: FREE_MONTHLY_LIMIT,
        resetAt: 'start of next UTC month',
      });
    }
  }

  req.apiKeyMeta = { hash, tier: meta.tier, email: meta.email };
  next();
}

/**
 * Return monthly usage stats for an API key (for dashboard).
 */
export async function getUsageStats(hash) {
  const redis    = getRedis();
  const usageKey = `usage:${hash}:${monthKey()}`;
  const count    = parseInt((await redis.get(usageKey)) ?? '0', 10);
  const meta     = await redis.hgetall(`apikey:${hash}`);
  return { count, tier: meta?.tier ?? 'unknown', limit: FREE_MONTHLY_LIMIT };
}

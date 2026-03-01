// Single-use nullifier store.
// Uses Redis when available; falls back to an in-memory Set when Redis is
// not running (dev / demo mode). The in-memory store resets on server restart
// but still prevents replay within a session.
// In production, run Redis so spent nullifiers survive restarts.

import Redis from 'ioredis';

// ── In-memory fallback ────────────────────────────────────────────────────────
const memStore = new Set();

// ── Redis (optional) ──────────────────────────────────────────────────────────
let redis = null;
let redisReady = false;

function initRedis() {
  if (redis) return;
  redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379', {
    lazyConnect:        true,
    enableOfflineQueue: false,
    connectTimeout:     2000,
    maxRetriesPerRequest: 1,
  });
  redis.on('ready', () => { redisReady = true;  console.log('[redis] connected'); });
  redis.on('error', ()  => { redisReady = false; });
  redis.connect().catch(() => {
    console.warn('[redis] not available — using in-memory nullifier store (demo mode)');
  });
}

export function getRedis() {
  initRedis();
  return redis;
}

// Keep nullifiers for 7 days so a credential can't be replayed after expiry.
const NULLIFIER_RETENTION_SECONDS = 7 * 24 * 60 * 60;

/**
 * Atomically check and mark a nullifier as spent.
 * Returns true if the nullifier was fresh (just spent), false if already used.
 */
export async function spendNullifier(nullifier) {
  if (redisReady) {
    try {
      const key    = `nul:${nullifier}`;
      const result = await redis.set(key, '1', 'NX', 'EX', NULLIFIER_RETENTION_SECONDS);
      return result === 'OK';
    } catch {
      // Redis hiccup — fall through to in-memory
    }
  }
  // In-memory fallback
  if (memStore.has(nullifier)) return false;
  memStore.add(nullifier);
  return true;
}

/**
 * Check whether a nullifier has been spent without spending it.
 */
export async function isNullifierSpent(nullifier) {
  if (redisReady) {
    try {
      return (await redis.exists(`nul:${nullifier}`)) === 1;
    } catch { /* fall through */ }
  }
  return memStore.has(nullifier);
}

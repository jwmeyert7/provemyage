// Single-use nullifier store backed by Redis.
// A nullifier is a deterministic hash output from the ZK circuit.
// Once spent it must never be accepted again — prevents QR replay attacks.

import Redis from 'ioredis';

let redis;

export function getRedis() {
  if (!redis) {
    redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379', {
      lazyConnect: false,
      enableOfflineQueue: true,
    });
    redis.on('error', err => console.error('[redis]', err.message));
  }
  return redis;
}

const TTL = Number(process.env.PROOF_TTL_SECONDS ?? 60);
// Keep nullifiers for 7 days so an expired credential can't be replayed
// even if the Redis key outlives the 60-second window.
const NULLIFIER_RETENTION_SECONDS = 7 * 24 * 60 * 60;

/**
 * Atomically check and mark a nullifier as spent.
 * Returns true if the nullifier was fresh (just spent), false if already used.
 */
export async function spendNullifier(nullifier) {
  const key = `nul:${nullifier}`;
  // SET key value NX EX ttl — only sets if key does not exist
  const result = await getRedis().set(key, '1', 'NX', 'EX', NULLIFIER_RETENTION_SECONDS);
  return result === 'OK'; // OK = was fresh; null = already existed
}

/**
 * Check whether a nullifier has been spent without spending it.
 * Used for debugging/dashboard only — verification always uses spendNullifier.
 */
export async function isNullifierSpent(nullifier) {
  const key = `nul:${nullifier}`;
  return (await getRedis().exists(key)) === 1;
}

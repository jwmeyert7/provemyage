// Verifier analytics dashboard API.
// Provides per-API-key statistics: verifications over time, result breakdown.

import { Router } from 'express';
import { getRedis } from './nullifier.js';
import { getUsageStats } from './auth.js';
import { requireApiKey } from './auth.js';

export const dashboardRouter = Router();

// GET /dashboard/stats - current month usage for the authenticated verifier
dashboardRouter.get('/stats', requireApiKey, async (req, res) => {
  try {
    const stats = await getUsageStats(req.apiKeyMeta.hash);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /dashboard/history - last 30 verification events (stored as a Redis list)
dashboardRouter.get('/history', requireApiKey, async (req, res) => {
  try {
    const redis = getRedis();
    const listKey = `history:${req.apiKeyMeta.hash}`;
    const raw = await redis.lrange(listKey, 0, 29);
    const events = raw.map(r => JSON.parse(r));
    res.json({ events });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Record a verification event in the dashboard history.
 * Called internally by the /verify route.
 */
export async function recordEvent(hash, { ageRangeLabel, verified, timestamp }) {
  if (!hash) return;
  const redis   = getRedis();
  const listKey = `history:${hash}`;
  const entry   = JSON.stringify({ ageRangeLabel, verified, timestamp, recordedAt: Date.now() });
  await redis.lpush(listKey, entry);
  await redis.ltrim(listKey, 0, 999);  // keep last 1000 events
  await redis.expire(listKey, 90 * 24 * 60 * 60); // 90 day retention
}

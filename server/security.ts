import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const attempts = new Map<string, { count: number; resetAt: number }>();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

export function clientKey(req: any, email = "") {
  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  return createHash("sha256").update(`${ip}|${email.trim().toLowerCase()}`).digest("hex");
}
export function checkLoginRateLimit(key: string) {
  const now = Date.now();
  const state = attempts.get(key);
  if (!state || state.resetAt <= now) { attempts.set(key, { count: 0, resetAt: now + WINDOW_MS }); return { allowed: true, retryAfterSeconds: 0 }; }
  return { allowed: state.count < MAX_ATTEMPTS, retryAfterSeconds: Math.ceil((state.resetAt - now) / 1000) };
}
export function recordLoginAttempt(key: string, successful: boolean) {
  if (successful) { attempts.delete(key); return; }
  const now = Date.now();
  const state = attempts.get(key);
  if (!state || state.resetAt <= now) attempts.set(key, { count: 1, resetAt: now + WINDOW_MS });
  else state.count += 1;
}
export function resetRateLimits() { attempts.clear(); }
export function issueCsrfToken() { return randomBytes(32).toString("hex"); }
export function safeEqual(a: string | undefined, b: string | undefined) {
  if (!a || !b) return false;
  const left = Buffer.from(a); const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

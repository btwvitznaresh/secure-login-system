import { randomBytes } from "node:crypto";
import { parse } from "cookie";
import type { Express, Request, Response } from "express";
import { upsertUser, createAuthSession, getUserByOpenId, hashSessionToken } from "./db";

export type SocialProvider = "google" | "github";
const STATE_COOKIE = "social_oauth_state";
const SESSION_COOKIE = "local_session";
export const SOCIAL_STATE_COOKIE_MAX_AGE_MS = 10 * 60 * 1000;
export const SOCIAL_SESSION_COOKIE_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7;
const configs: Record<SocialProvider, { authorizationEndpoint: string; scope: string }> = {
  google: { authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth", scope: "openid email profile" },
  github: { authorizationEndpoint: "https://github.com/login/oauth/authorize", scope: "read:user user:email" },
};
function enabled(provider: SocialProvider) { return Boolean(process.env[`${provider.toUpperCase()}_OAUTH_CLIENT_ID`] && process.env[`${provider.toUpperCase()}_OAUTH_CLIENT_SECRET`] && process.env.APP_BASE_URL); }
export function socialProviderConfig(provider: SocialProvider) { return { provider, enabled: enabled(provider), startPath: `/api/oauth/${provider}/start` }; }
export function socialProviders() { return (["google", "github"] as SocialProvider[]).map(socialProviderConfig); }
function callbackUrl(provider: SocialProvider) { return `${process.env.APP_BASE_URL!.replace(/\/$/, "")}/api/oauth/${provider}/callback`; }
function cookieOptions(req: Request) { return { httpOnly: true, secure: req.protocol === "https", sameSite: "lax" as const, path: "/", maxAge: SOCIAL_STATE_COOKIE_MAX_AGE_MS }; }
function redirect(res: Response, url: string) { res.redirect(302, url); }
async function exchange(provider: SocialProvider, code: string, redirectUri: string) {
  const id = process.env[`${provider.toUpperCase()}_OAUTH_CLIENT_ID`]!; const secret = process.env[`${provider.toUpperCase()}_OAUTH_CLIENT_SECRET`]!;
  if (provider === "google") { const token = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: id, client_secret: secret, redirect_uri: redirectUri, grant_type: "authorization_code" }) }).then(r => r.json() as Promise<any>); const info = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { authorization: `Bearer ${token.access_token}` } }).then(r => r.json() as Promise<any>); return { id: String(info.sub), email: info.email, name: info.name }; }
  const token = await fetch("https://github.com/login/oauth/access_token", { method: "POST", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ code, client_id: id, client_secret: secret, redirect_uri: redirectUri }) }).then(r => r.json() as Promise<any>); const headers = { authorization: `Bearer ${token.access_token}`, accept: "application/vnd.github+json", "user-agent": "secure-login-system" }; const info = await fetch("https://api.github.com/user", { headers }).then(r => r.json() as Promise<any>); const emails = await fetch("https://api.github.com/user/emails", { headers }).then(r => r.json() as Promise<any[]>); return { id: String(info.id), email: emails.find(e => e.primary && e.verified)?.email || info.email, name: info.name || info.login };
}
export function registerSocialOAuthRoutes(app: Express) {
  for (const provider of ["google", "github"] as SocialProvider[]) {
    app.get(`/api/oauth/${provider}/start`, (req: Request, res: Response) => { if (!enabled(provider)) { res.status(503).send("This provider is not configured."); return; } const state = randomBytes(32).toString("hex"); res.cookie(STATE_COOKIE, `${provider}:${state}`, cookieOptions(req)); const query = new URLSearchParams({ client_id: process.env[`${provider.toUpperCase()}_OAUTH_CLIENT_ID`]!, redirect_uri: callbackUrl(provider), response_type: "code", scope: configs[provider].scope, state }); redirect(res, `${configs[provider].authorizationEndpoint}?${query.toString()}`); });
    app.get(`/api/oauth/${provider}/callback`, async (req: Request, res: Response) => { const code = typeof req.query.code === "string" ? req.query.code : ""; const state = typeof req.query.state === "string" ? req.query.state : ""; const expected = parse(req.headers.cookie || "")[STATE_COOKIE]; if (!code || !state || expected !== `${provider}:${state}`) { res.status(403).send("Invalid OAuth state or callback."); return; } res.clearCookie(STATE_COOKIE, { path: "/" }); try { const identity = await exchange(provider, code, callbackUrl(provider)); if (!identity.id || !identity.email) { res.status(400).send("The provider did not return a verified email address."); return; } const openId = `oauth:${provider}:${identity.id}`.slice(0, 64); await upsertUser({ openId, email: identity.email, name: identity.name || null, loginMethod: provider, lastSignedIn: new Date() }); const raw = randomBytes(32).toString("hex"); const localUser = await getUserByOpenId(openId); if (!localUser) { res.status(500).send("Unable to create the social account."); return; } await createAuthSession(localUser.id, hashSessionToken(raw), new Date(Date.now() + SOCIAL_SESSION_COOKIE_MAX_AGE_MS), 1, { ipAddress: req.ip, userAgent: req.headers["user-agent"] }); res.cookie(SESSION_COOKIE, raw, { ...cookieOptions(req), maxAge: SOCIAL_SESSION_COOKIE_MAX_AGE_MS }); redirect(res, "/"); } catch (error) { console.error(`[OAuth:${provider}] callback failed`, error); res.status(502).send("Social sign-in could not be completed."); } });
  }
}

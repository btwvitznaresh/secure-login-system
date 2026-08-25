import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("./db", () => ({ upsertUser: vi.fn(), createAuthSession: vi.fn(), getUserByOpenId: vi.fn(async () => ({ id: 44 })), hashSessionToken: vi.fn((token: string) => `hash:${token}`) }));
import { registerSocialOAuthRoutes, socialProviders, SOCIAL_SESSION_COOKIE_MAX_AGE_MS, SOCIAL_STATE_COOKIE_MAX_AGE_MS } from "./socialOAuth";
import * as db from "./db";
const dbMock = vi.mocked(db);

type Handler = (req: any, res: any) => unknown;
function routes() { const handlers = new Map<string, Handler>(); const app = { get: vi.fn((path: string, handler: Handler) => handlers.set(path, handler)) } as any; registerSocialOAuthRoutes(app); return handlers; }
function response() { return { cookie: vi.fn(), clearCookie: vi.fn(), redirect: vi.fn(), status: vi.fn().mockReturnThis(), send: vi.fn() }; }

describe("social OAuth configuration", () => {
  beforeEach(() => { vi.clearAllMocks(); process.env.APP_BASE_URL = "https://auth.example.test"; process.env.GOOGLE_OAUTH_CLIENT_ID = "google-id"; process.env.GOOGLE_OAUTH_CLIENT_SECRET = "google-secret"; process.env.GITHUB_OAUTH_CLIENT_ID = "github-id"; process.env.GITHUB_OAUTH_CLIENT_SECRET = "github-secret"; });
  it("uses millisecond cookie lifetimes for state and sessions", () => { expect(SOCIAL_STATE_COOKIE_MAX_AGE_MS).toBe(10 * 60 * 1000); expect(SOCIAL_SESSION_COOKIE_MAX_AGE_MS).toBe(7 * 24 * 60 * 60 * 1000); });
  it("reports both configured providers", () => { expect(socialProviders()).toEqual([{ provider: "google", enabled: true, startPath: "/api/oauth/google/start" }, { provider: "github", enabled: true, startPath: "/api/oauth/github/start" }]); });
  it("sets a secure ten-minute state cookie on the Google start route", () => { const handler = routes().get("/api/oauth/google/start")!; const res = response(); handler({ protocol: "https" }, res); expect(res.cookie).toHaveBeenCalledWith("social_oauth_state", expect.stringMatching(/^google:/), expect.objectContaining({ httpOnly: true, secure: true, sameSite: "lax", maxAge: SOCIAL_STATE_COOKIE_MAX_AGE_MS })); expect(res.redirect).toHaveBeenCalledWith(302, expect.stringContaining("accounts.google.com")); });
  it("sets a seven-day local session cookie after a valid GitHub callback", async () => { const handler = routes().get("/api/oauth/github/callback")!; const res = response(); const state = "github:" + "b".repeat(64); vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce({ json: async () => ({ access_token: "access-token" }) }).mockResolvedValueOnce({ json: async () => ({ id: 99, email: "social@example.com", name: "Social User" }) }).mockResolvedValueOnce({ json: async () => [{ primary: true, verified: true, email: "social@example.com" }] })); await handler({ protocol: "https", ip: "127.0.0.1", headers: { cookie: `social_oauth_state=${state}`, "user-agent": "Test Browser" }, query: { code: "auth-code", state: state.slice(7) } }, res); expect(dbMock.createAuthSession).toHaveBeenCalledWith(44, expect.stringMatching(/^hash:/), expect.any(Date), 1, expect.objectContaining({ ipAddress: "127.0.0.1" })); expect(res.cookie).toHaveBeenCalledWith("local_session", expect.any(String), expect.objectContaining({ httpOnly: true, secure: true, maxAge: SOCIAL_SESSION_COOKIE_MAX_AGE_MS })); expect(res.redirect).toHaveBeenCalledWith(302, "/"); vi.unstubAllGlobals(); });
});

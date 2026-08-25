import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("./db", () => ({ getUserBySessionToken: vi.fn(), getActiveSessions: vi.fn(), revokeAuthSession: vi.fn(), revokeOtherAuthSessions: vi.fn(), hashSessionToken: vi.fn((token: string) => token === "current" ? "hash:current" : "hash:other") }));
import { appRouter } from "./routers";
import * as db from "./db";
const dbMock = vi.mocked(db); const csrfToken = "a".repeat(64);
function context(cookie = "") { return { req: { protocol: "https", headers: { cookie: `${cookie}; local_csrf=${csrfToken}` } }, res: { cookie: vi.fn(), setHeader: vi.fn(), clearCookie: vi.fn() } } as any; }
const user = { id: 12, email: "member@example.com", role: "user", name: "Member", emailVerified: 1, twoFactorEnabled: 0, sessionTwoFactorVerified: 1 };

describe("account session controls", () => {
  beforeEach(() => vi.clearAllMocks());
  it("lists sessions with current-session marking and redacted token hashes", async () => { dbMock.getUserBySessionToken.mockResolvedValue(user as any); dbMock.getActiveSessions.mockResolvedValue([{ id: 1, tokenHash: "hash:current", expiresAt: new Date(Date.now() + 10000), createdAt: new Date(), ipAddress: "127.0.0.1", userAgent: "Browser" }] as any); const result = await appRouter.createCaller(context("local_session=current")).account.sessions({ csrfToken }); expect(result[0]).toMatchObject({ id: 1, isCurrent: true, userAgent: "Browser" }); expect(result[0]).not.toHaveProperty("tokenHash"); });
  it("revokes only a session belonging to the signed-in user", async () => { dbMock.getUserBySessionToken.mockResolvedValue(user as any); const result = await appRouter.createCaller(context("local_session=current")).account.revokeSession({ sessionId: 9, csrfToken }); expect(result).toEqual({ success: true }); expect(dbMock.revokeAuthSession).toHaveBeenCalledWith(12, 9); });
});

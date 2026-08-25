import { beforeEach, describe, expect, it, vi } from "vitest";
import bcrypt from "bcryptjs";

vi.mock("./db", () => ({
  getLocalUserByEmail: vi.fn(),
  createLocalUser: vi.fn(),
  createAuthSession: vi.fn(),
  deleteAuthSession: vi.fn(),
  getUserBySessionToken: vi.fn(),
  hashSessionToken: vi.fn((token: string) => `hash:${token}`),
  updateTwoFactorEnrollment: vi.fn(),
}));

import { appRouter, totp } from "./routers";
import * as db from "./db";

const dbMock = vi.mocked(db);

function context(cookie = "") {
  const cookies: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];
  const ctx = {
    user: undefined,
    req: { protocol: "https", headers: { cookie } },
    res: {
      cookie: (name: string, value: string, options: Record<string, unknown>) => cookies.push({ name, value, options }),
      clearCookie: vi.fn(),
      setHeader: vi.fn(),
    },
  } as any;
  return { ctx, cookies };
}

const user = {
  id: 7,
  openId: "local_7",
  email: "alex@example.com",
  name: "Alex",
  passwordHash: "$2b$12$abcdefghijklmnopqrstuuQmF4p3JcV0Hf2J5eZxY8vYJ3b4tK6",
  loginMethod: "local",
  role: "user",
  twoFactorEnabled: 0,
  twoFactorSecret: "JBSWY3DPEHPK3PXP",
  twoFactorEnrollmentId: "12345678901234567890123456789012",
};

describe("local authentication", () => {
  beforeEach(() => vi.clearAllMocks());

  it("rejects malformed registration input before touching the data layer", async () => {
    const { ctx } = context();
    await expect(appRouter.createCaller(ctx).localAuth.register({ email: "not-an-email", password: "short" })).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(dbMock.getLocalUserByEmail).not.toHaveBeenCalled();
  });

  it("handles duplicate email registration without account enumeration", async () => {
    dbMock.getLocalUserByEmail.mockResolvedValue(user as any);
    const { ctx } = context();
    const result = await appRouter.createCaller(ctx).localAuth.register({ email: "Alex@Example.com", password: "correct horse battery staple" });
    expect(result.accepted).toBe(true);
    expect(result.message).toContain("eligible");
    expect(dbMock.createLocalUser).not.toHaveBeenCalled();
  });

  it("hashes a new password and establishes an HTTP-only session", async () => {
    dbMock.getLocalUserByEmail.mockResolvedValue(undefined);
    dbMock.createLocalUser.mockResolvedValue(7);
    const { ctx, cookies } = context();
    const result = await appRouter.createCaller(ctx).localAuth.register({ email: "Alex@Example.com", password: "correct horse battery staple", name: "Alex" });
    expect(result.accepted).toBe(true);
    expect(dbMock.createLocalUser).toHaveBeenCalledWith("alex@example.com", expect.stringMatching(/^\$2[aby]\$/), "Alex");
    expect(dbMock.createAuthSession).not.toHaveBeenCalled();
    expect(cookies).toHaveLength(0);
  });

  it("returns a generic error for an incorrect password", async () => {
    dbMock.getLocalUserByEmail.mockResolvedValue(user as any);
    const { ctx } = context();
    await expect(appRouter.createCaller(ctx).localAuth.login({ email: "alex@example.com", password: "wrong password" })).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(dbMock.createAuthSession).not.toHaveBeenCalled();
  });

  it("creates a session after a valid password", async () => {
    const hash = await bcrypt.hash("password", 4);
    dbMock.getLocalUserByEmail.mockResolvedValue({ ...user, passwordHash: hash } as any);
    const { ctx, cookies } = context();
    const result = await appRouter.createCaller(ctx).localAuth.login({ email: "alex@example.com", password: "password" });
    expect(result.requiresTwoFactor).toBe(false);
    expect(dbMock.createAuthSession).toHaveBeenCalledTimes(1);
    expect(cookies[0]?.name).toBe("local_session");
  });

  it("protects account access when no valid session exists", async () => {
    dbMock.getUserBySessionToken.mockResolvedValue(undefined);
    const { ctx } = context("local_session=expired-token");
    await expect(appRouter.createCaller(ctx).account.overview()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("persists a pending 2FA enrollment for an authenticated user", async () => {
    dbMock.getUserBySessionToken.mockResolvedValue(user as any);
    const { ctx } = context("local_session=active-token");
    const result = await appRouter.createCaller(ctx).twoFactor.beginEnrollment();
    expect(result.ready).toBe(true);
    expect(result.secret).toMatch(/^[A-Z2-7]+$/);
    expect(result.otpauthUri).toContain("otpauth://totp/");
    expect(dbMock.updateTwoFactorEnrollment).toHaveBeenCalledWith(7, expect.objectContaining({ twoFactorEnabled: 0, twoFactorEnrollmentId: expect.any(String), twoFactorSecret: expect.any(String) }));
  });

  it("persists successful 2FA verification and recovery-code hashes", async () => {
    dbMock.getUserBySessionToken.mockResolvedValue(user as any);
    const { ctx } = context("local_session=active-token");
    const code = totp(user.twoFactorSecret, Math.floor(Date.now() / 1000 / 30));
    const result = await appRouter.createCaller(ctx).twoFactor.verifyEnrollment({ enrollmentId: user.twoFactorEnrollmentId, code });
    expect(result.accepted).toBe(true);
    expect(result.recoveryCodes).toHaveLength(8);
    expect(dbMock.updateTwoFactorEnrollment).toHaveBeenCalledWith(7, expect.objectContaining({ twoFactorEnabled: 1, twoFactorEnrollmentId: null, recoveryCodesHash: expect.stringMatching(/^\$2[aby]\$/) }));
  });

  it("validates the 2FA verification code shape", async () => {
    dbMock.getUserBySessionToken.mockResolvedValue(user as any);
    const { ctx } = context("local_session=active-token");
    await expect(appRouter.createCaller(ctx).twoFactor.verifyEnrollment({ enrollmentId: "12345678901234567890123456789012", code: "12" })).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });

  it("deletes the active session and expires the cookie on logout", async () => {
    const { ctx, cookies } = context("local_session=active-token");
    const result = await appRouter.createCaller(ctx).localAuth.logout();
    expect(result).toEqual({ success: true });
    expect(dbMock.deleteAuthSession).toHaveBeenCalledWith("active-token");
    expect(cookies[0]?.options).toMatchObject({ maxAge: 0, httpOnly: true, secure: true });
  });
});

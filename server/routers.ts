import bcrypt from "bcryptjs";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { parse } from "cookie";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { getLocalUserByEmail, createLocalUser, createAuthSession, deleteAuthSession, getUserBySessionToken, hashSessionToken, updateTwoFactorEnrollment } from "./db";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";

export const LOCAL_SESSION_COOKIE = "local_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const emailSchema = z.string().trim().toLowerCase().email("Enter a valid email address").max(320);
const passwordSchema = z.string().min(12, "Use at least 12 characters").max(128);
const nameSchema = z.string().trim().min(1).max(80).optional();

function cookieOptions(req: any) {
  return { httpOnly: true, secure: req.protocol === "https", sameSite: "lax" as const, path: "/", maxAge: SESSION_TTL_MS / 1000 };
}
function readLocalToken(req: any) { return parse(req.headers.cookie || "")[LOCAL_SESSION_COOKIE]; }
function safeUser(user: any) { return user && { id: user.id, email: user.email, name: user.name, role: user.role, twoFactorEnabled: Boolean(user.twoFactorEnabled) }; }
async function establishSession(ctx: any, userId: number) {
  const raw = randomBytes(32).toString("hex");
  await createAuthSession(userId, hashSessionToken(raw), new Date(Date.now() + SESSION_TTL_MS));
  ctx.res.cookie(LOCAL_SESSION_COOKIE, raw, cookieOptions(ctx.req));
}
async function currentLocalUser(ctx: any) { const token = readLocalToken(ctx.req); return token ? getUserBySessionToken(token) : undefined; }
function base32(bytes: Buffer) { const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, value = 0, output = ""; for (let index = 0; index < bytes.length; index++) { const byte = bytes[index] ?? 0; value = (value << 8) | byte; bits += 8; while (bits >= 5) { output += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; } } if (bits) output += alphabet[(value << (5 - bits)) & 31]; return output; }
function base32Decode(value: string) { const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, buffer = 0; const out: number[] = []; for (const char of value.replace(/=+$/, "").toUpperCase()) { const index = alphabet.indexOf(char); if (index < 0) throw new Error("Invalid TOTP secret"); buffer = (buffer << 5) | index; bits += 5; if (bits >= 8) { out.push((buffer >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
export function totp(secret: string, counter: number) { const data = Buffer.alloc(8); data.writeBigUInt64BE(BigInt(counter)); const digest = createHmac("sha1", base32Decode(secret)).update(data).digest(); const offset = digest[digest.length - 1] & 15; const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000; return String(code).padStart(6, "0"); }
function validTotp(secret: string, code: string) { const now = Math.floor(Date.now() / 1000 / 30); return [-1, 0, 1].some(delta => { const expected = Buffer.from(totp(secret, now + delta)); const supplied = Buffer.from(code); return expected.length === supplied.length && timingSafeEqual(expected, supplied); }); }

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => { const cookieOptions = getSessionCookieOptions(ctx.req); ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 }); return { success: true } as const; }),
  }),
  localAuth: router({
    me: publicProcedure.query(async ({ ctx }) => safeUser(await currentLocalUser(ctx))),
    register: publicProcedure.input(z.object({ email: emailSchema, password: passwordSchema, name: nameSchema })).mutation(async ({ input, ctx }) => {
      if (await getLocalUserByEmail(input.email)) return { accepted: true, message: "If this address is eligible, we’ll continue with account setup." };
      const passwordHash = await bcrypt.hash(input.password, 12);
      try {
        await createLocalUser(input.email, passwordHash, input.name);
        return { accepted: true, message: "If this address is eligible, we’ll continue with account setup." };
      } catch { return { accepted: true, message: "If this address is eligible, we’ll continue with account setup." }; }
    }),
    login: publicProcedure.input(z.object({ email: emailSchema, password: z.string().min(1).max(128) })).mutation(async ({ input, ctx }) => {
      const user = await getLocalUserByEmail(input.email);
      const valid = user?.passwordHash ? await bcrypt.compare(input.password, user.passwordHash) : false;
      if (!user || !valid) throw new TRPCError({ code: "UNAUTHORIZED", message: "Email or password is incorrect." });
      await establishSession(ctx, user.id);
      return { user: safeUser(user), requiresTwoFactor: Boolean(user.twoFactorEnabled) };
    }),
    logout: publicProcedure.mutation(async ({ ctx }) => { const token = readLocalToken(ctx.req); if (token) await deleteAuthSession(token); ctx.res.cookie(LOCAL_SESSION_COOKIE, "", { ...cookieOptions(ctx.req), maxAge: 0 }); return { success: true } as const; }),
  }),
  account: router({
    overview: publicProcedure.query(async ({ ctx }) => { const user = await currentLocalUser(ctx); if (!user) throw new TRPCError({ code: "UNAUTHORIZED", message: "Please sign in." }); return { user: safeUser(user), security: { twoFactorReady: true, recoveryGuidance: "Store recovery codes offline and never share them." } }; }),
  }),
  twoFactor: router({
    status: publicProcedure.query(async ({ ctx }) => { const user = await currentLocalUser(ctx); return { authenticated: Boolean(user), enabled: user ? Boolean(user.twoFactorEnabled) : false, ready: true, guidance: "TOTP enrollment and recovery-code verification can be connected here without changing the session model." }; }),
    beginEnrollment: publicProcedure.mutation(async ({ ctx }) => { const user = await currentLocalUser(ctx); if (!user) throw new TRPCError({ code: "UNAUTHORIZED", message: "Please sign in." }); const secret = base32(randomBytes(20)); const enrollmentId = randomBytes(16).toString("hex"); await updateTwoFactorEnrollment(user.id, { twoFactorSecret: secret, twoFactorEnrollmentId: enrollmentId, twoFactorEnabled: 0 }); return { ready: true, enrollmentId, secret, otpauthUri: `otpauth://totp/Haven:${encodeURIComponent(user.email || "account")}?secret=${secret}&issuer=Haven`, guidance: "Add this secret to a TOTP authenticator, then submit the six-digit code. Save recovery codes offline." }; }),
    verifyEnrollment: publicProcedure.input(z.object({ enrollmentId: z.string().length(32), code: z.string().regex(/^\d{6}$/, "Enter a six-digit verification code") })).mutation(async ({ ctx, input }) => { const user = await currentLocalUser(ctx); if (!user) throw new TRPCError({ code: "UNAUTHORIZED", message: "Please sign in." }); if (user.twoFactorEnrollmentId !== input.enrollmentId || !user.twoFactorSecret || !validTotp(user.twoFactorSecret, input.code)) throw new TRPCError({ code: "BAD_REQUEST", message: "That verification code is invalid or expired." }); const recoveryCodes = Array.from({ length: 8 }, () => randomBytes(5).toString("hex")); await updateTwoFactorEnrollment(user.id, { twoFactorEnabled: 1, twoFactorEnrollmentId: null, recoveryCodesHash: await bcrypt.hash(recoveryCodes.join(","), 12) }); return { ready: true, accepted: true, recoveryCodes, guidance: "Download or print these recovery codes now. They will not be shown again." }; }),
  }),
});
export type AppRouter = typeof appRouter;

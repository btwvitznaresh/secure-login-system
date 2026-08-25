import { and, eq, gt } from "drizzle-orm";
import { createHash } from "node:crypto";
import { drizzle } from "drizzle-orm/mysql2";
import { authSessions, InsertUser, users } from "../drizzle/schema";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export async function getLocalUserByEmail(email: string) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(users).where(eq(users.email, normalizeEmail(email))).limit(1);
  return rows[0];
}

export async function createLocalUser(email: string, passwordHash: string, name?: string) {
  const db = await getDb();
  if (!db) throw new Error("Database is not available");
  const result = await db.insert(users).values({
    openId: `local_${crypto.randomUUID()}`,
    email: normalizeEmail(email),
    name: name?.trim() || null,
    passwordHash,
    loginMethod: "local",
  });
  return Number(result[0].insertId);
}

export function hashSessionToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export async function createAuthSession(userId: number, tokenHash: string, expiresAt: Date, twoFactorVerified = 1) {
  const db = await getDb();
  if (!db) throw new Error("Database is not available");
  await db.insert(authSessions).values({ userId, tokenHash, expiresAt, twoFactorVerified });
}

export async function getUserBySessionToken(token: string) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select({ user: users, session: authSessions }).from(authSessions)
    .innerJoin(users, eq(authSessions.userId, users.id))
    .where(and(eq(authSessions.tokenHash, hashSessionToken(token)), gt(authSessions.expiresAt, new Date())))
    .limit(1);
  return rows[0] ? { ...rows[0].user, sessionTwoFactorVerified: rows[0].session.twoFactorVerified } : undefined;
}

export async function deleteAuthSession(token: string) {
  const db = await getDb();
  if (!db) return;
  await db.delete(authSessions).where(eq(authSessions.tokenHash, hashSessionToken(token)));
}

export async function verifyAuthSessionTwoFactor(token: string) {
  const db = await getDb();
  if (!db) return;
  await db.update(authSessions).set({ twoFactorVerified: 1 }).where(eq(authSessions.tokenHash, hashSessionToken(token)));
}

export async function setEmailVerificationToken(userId: number, tokenHash: string, expiresAt: Date) {
  const db = await getDb(); if (!db) throw new Error("Database is not available");
  await db.update(users).set({ emailVerificationTokenHash: tokenHash, emailVerificationExpiresAt: expiresAt }).where(eq(users.id, userId));
}
export async function consumeEmailVerificationToken(tokenHash: string) {
  const db = await getDb(); if (!db) return undefined;
  const rows = await db.select().from(users).where(and(eq(users.emailVerificationTokenHash, tokenHash), gt(users.emailVerificationExpiresAt, new Date()))).limit(1);
  const user = rows[0]; if (!user) return undefined;
  await db.update(users).set({ emailVerified: 1, emailVerificationTokenHash: null, emailVerificationExpiresAt: null }).where(eq(users.id, user.id));
  return user;
}
export async function setPasswordResetToken(userId: number, tokenHash: string, expiresAt: Date) {
  const db = await getDb(); if (!db) throw new Error("Database is not available");
  await db.update(users).set({ passwordResetTokenHash: tokenHash, passwordResetExpiresAt: expiresAt }).where(eq(users.id, userId));
}
export async function getUserByPasswordResetToken(tokenHash: string) {
  const db = await getDb(); if (!db) return undefined;
  const rows = await db.select().from(users).where(and(eq(users.passwordResetTokenHash, tokenHash), gt(users.passwordResetExpiresAt, new Date()))).limit(1);
  return rows[0];
}
export async function completePasswordReset(userId: number, passwordHash: string) {
  const db = await getDb(); if (!db) throw new Error("Database is not available");
  await db.update(users).set({ passwordHash, passwordResetTokenHash: null, passwordResetExpiresAt: null }).where(eq(users.id, userId));
}

export async function updateTwoFactorEnrollment(userId: number, data: { twoFactorSecret?: string; twoFactorEnrollmentId?: string | null; twoFactorEnabled?: number; recoveryCodesHash?: string }) {
  const db = await getDb();
  if (!db) throw new Error("Database is not available");
  await db.update(users).set(data).where(eq(users.id, userId));
}


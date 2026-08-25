import { int, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  emailVerified: int("emailVerified").default(0).notNull(),
  emailVerificationTokenHash: varchar("emailVerificationTokenHash", { length: 64 }),
  emailVerificationExpiresAt: timestamp("emailVerificationExpiresAt"),
  passwordResetTokenHash: varchar("passwordResetTokenHash", { length: 64 }),
  passwordResetExpiresAt: timestamp("passwordResetExpiresAt"),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
  passwordHash: varchar("passwordHash", { length: 255 }),
  twoFactorEnabled: int("twoFactorEnabled").default(0).notNull(),
  twoFactorSecret: varchar("twoFactorSecret", { length: 255 }),
  twoFactorEnrollmentId: varchar("twoFactorEnrollmentId", { length: 64 }),
  recoveryCodesHash: text("recoveryCodesHash"),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const authSessions = mysqlTable("auth_sessions", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  tokenHash: varchar("tokenHash", { length: 64 }).notNull().unique(),
  expiresAt: timestamp("expiresAt").notNull(),
  twoFactorVerified: int("twoFactorVerified").default(1).notNull(),
  ipAddress: varchar("ipAddress", { length: 64 }),
  userAgent: varchar("userAgent", { length: 512 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type AuthSession = typeof authSessions.$inferSelect;

export const securityEvents = mysqlTable("security_events", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  eventType: varchar("eventType", { length: 64 }).notNull(),
  ipAddress: varchar("ipAddress", { length: 64 }),
  userAgent: varchar("userAgent", { length: 512 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type SecurityEvent = typeof securityEvents.$inferSelect;

// 2FA fields are intentionally ready for a future TOTP provider integration.
// Secrets and recovery-code material must be encrypted/hashed before production use.

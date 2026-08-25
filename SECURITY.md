# Security and setup notes

This application provides a local email/password authentication path alongside the template's existing Manus OAuth plumbing. Local passwords are accepted only after Zod validation and are stored as **bcrypt hashes** with a cost factor of 12; the raw password is never written to the database or returned to the client.

All local-account queries are made through the Drizzle data layer. Drizzle generates parameterized SQL for the email lookup, account insert, session insert, session join, and session deletion paths, so user input is not concatenated into SQL strings. Email addresses are normalized to lowercase before lookup and insert, and duplicate registration returns an explicit conflict response.

Local sessions use 32 random bytes as the browser token and store only a SHA-256 token digest in `auth_sessions`. The browser receives the token in an HTTP-only cookie with `SameSite=Lax`, `Secure` under HTTPS, a seven-day expiry, and root path scope. Account access queries the session digest and expiry on the server. Logout deletes the session row and expires the cookie, so the active session is invalidated rather than merely hidden in the UI.

The 2FA router is intentionally **ready but not enabled**. It exposes status, enrollment-start, and six-digit verification contracts, but it does not turn on account state until a reviewed TOTP provider is integrated. Before enabling it in production, encrypt TOTP secrets at rest, hash recovery codes, rate-limit verification attempts, prevent replay, issue recovery codes only once, and provide a clear recovery process that does not bypass identity verification.

## Local development

Install dependencies and run the development server with:

```bash
pnpm install
pnpm dev
```

Run static checks and tests with:

```bash
pnpm check
pnpm test
```

The database migration for `auth_sessions` and the user security fields is generated under `drizzle/`. Configure `DATABASE_URL` and the template's required secrets through the project environment rather than committing a `.env` file.

## Production checklist

Use HTTPS, keep `JWT_SECRET` and `DATABASE_URL` out of source control, set a strong production database credential, add CSRF protection appropriate to the deployment architecture, add login and registration rate limiting, consider generic duplicate-account messaging where account enumeration is a concern, and monitor failed login events. The current UI is a secure-flow prototype and should receive a security review before handling sensitive production accounts.

## Additional account-protection controls

Local login attempts are bounded to five failures per fifteen-minute window per normalized email and client-address key. Successful authentication clears that key. For horizontally scaled production deployments, move this limiter to a shared store such as Redis so limits apply consistently across instances.

State-changing local-auth procedures require a server-issued double-submit CSRF token. The token is stored in an HTTP-only cookie and must also be submitted in the tRPC input; validation uses a constant-time comparison. Keep the application on HTTPS and preserve the secure cookie settings in production.

TOTP enrollment uses the `otplib` implementation with a 160-bit secret, an `otpauth://` URI, a six-digit verification step, and a seven-day session challenge state. When enabled, account access remains blocked until the current session completes TOTP verification or redeems one unused recovery code. Recovery codes are individually bcrypt-hashed and the redeemed hash is removed from the stored JSON array.

Registration and password-reset requests use non-enumerating responses. Registration creates a short-lived email-verification token, while reset requests create a short-lived password-reset token. The server sends these tokens through `AUTH_EMAIL_WEBHOOK_URL`, a provider-agnostic HTTPS webhook that your transactional email service should translate into user-facing links. The links should point back to the app with the token as a one-time parameter. In development, delivery is logged as prepared rather than sent.

## Profile security dashboard

The authenticated profile view lists only unexpired sessions and displays minimal client metadata. The current session is marked and cannot be revoked from its own row; other sessions can be revoked individually, or all other sessions can be invalidated while preserving the current session. Session identifiers and token digests are never sent to the browser.

## Password-strength feedback

Registration and password-reset forms provide real-time guidance based on length, mixed case, digits, symbols, and repeated-character patterns. This is advisory UX only; the server remains authoritative and requires the configured password policy.

## Google and GitHub OAuth2

Google and GitHub sign-in start at `/api/oauth/google/start` and `/api/oauth/github/start`. Configure each provider's client ID and secret plus an HTTPS `APP_BASE_URL`; register exact callback URLs at `/api/oauth/{provider}/callback`. Provider secrets remain server-side. Each flow creates a random state value, stores it in an HTTP-only cookie, validates it on callback, exchanges the authorization code server-side, requires a verified email, and then creates the same local HTTP-only session used by password login.

## Security activity data

The `security_events` table stores minimal audit metadata for successful sign-ins, 2FA completion, recovery-code use, password resets, and logout. It intentionally excludes credentials, access tokens, raw session tokens, and recovery-code material. The profile dashboard shows the latest events for the signed-in account only.

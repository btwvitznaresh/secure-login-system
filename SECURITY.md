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

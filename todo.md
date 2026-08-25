# Project TODO

- [x] Define registration and login validation rules and user-facing error states
- [x] Add duplicate-account handling without leaking sensitive account details
- [x] Add bcrypt password hashing and password verification
- [x] Add parameterized database-layer queries for local account records
- [x] Add secure HTTP-only session creation, lookup, expiry, and invalidation
- [x] Add protected account page and logout action
- [x] Add 2FA-ready enrollment and verification model with recovery guidance
- [x] Build polished responsive authentication UI and empty/loading/error states
- [x] Add automated tests for validation, duplicate accounts, hashing, sessions, and logout
- [x] Write setup and security-use documentation
- [x] Run type checks, tests, and visual verification
- [x] Replace duplicate-registration responses with non-enumerating behavior
- [x] Implement persisted TOTP-ready enrollment and verification with recovery-code storage
- [x] Add and apply the missing recovery-code schema migration
- [x] Add tests for non-enumerating registration and persisted 2FA-ready behavior

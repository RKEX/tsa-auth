# Render Firebase authentication service

This directory is an independently installable Node.js service. The Next.js
site, admin APIs, Turso access, contact flow, Google Sheets, uploads, and other
application behavior remain on Cloudflare Workers. This service only verifies
Firebase ID tokens for admin login and signs the existing seven-day admin
session format.

## Trust boundary and session contract

1. The browser signs in with Firebase and sends its Firebase ID token to the
   same-origin Cloudflare route `/api/admin/auth/session`.
2. That route calls `POST /auth/session` over HTTPS, authenticating with
   `AUTH_BACKEND_SHARED_SECRET`. The browser does not receive this credential,
   the Render URL response does not set cookies, and no CORS access is granted.
3. Render verifies the Firebase token with Firebase Admin including revocation,
   validates its Firebase project claims, and enforces the configured existing
   admin email allowlist.
4. Render signs the same HMAC-SHA256 payload, seven-day expiry, and
   `ADMIN_SESSION_SECRET` contract used by the Cloudflare app. Cloudflare
   verifies the returned token locally before setting the existing host-only,
   HttpOnly, SameSite=Lax cookie. The session token is never returned to the
   browser.
5. Protected APIs continue verifying that cookie locally. Logout remains the
   existing Cloudflare cookie-clear operation. Because sessions are stateless,
   clearing the browser cookie does not revoke a copied token; the browser
   never receives that token, and Firebase revocation is checked at login.

Configure the same existing `ADMIN_SESSION_SECRET` in Render and the Worker.
Use a separately generated, high-entropy `AUTH_BACKEND_SHARED_SECRET` in
Render and as a Cloudflare Worker secret. Do not reuse a Firebase, Sheets, or
other credential. The backend has no direct Turso or Sheets access.

## Requirements and local commands

Node.js 24.x is required (`.node-version` pins 24.21.0). Use npm 11 or newer.
The backend has its own `package-lock.json`; do not change the parent Bun lock.

```sh
npm ci
npm run build
npm test
npm start
```

`npm test` builds TypeScript and runs the compiled Node test suite. Tests use
mocked Firebase verification and synthetic credentials only. No live Firebase,
Render, email, database, or Cloudflare service is contacted.

For local use, copy `.env.example` to `.env` and fill it with dedicated test
credentials. Never use production secrets in local tests. `PORT` defaults to
10000; Render provides its own port. `GET` and `HEAD /healthz` return a minimal
liveness response. `GET /readyz` reports whether the process started with
valid configuration; it does not reveal configuration or call Firebase.

## Environment variables

| Name | Purpose |
| --- | --- |
| `NODE_ENV` | `production` on Render; defaults to `development`. |
| `PORT` | HTTP port; Render injects this at runtime. |
| `FIREBASE_PROJECT_ID` | Existing Firebase project that issues the Web ID tokens. |
| `FIREBASE_CLIENT_EMAIL` | Firebase Admin service-account identity. |
| `FIREBASE_PRIVATE_KEY` | Firebase Admin PEM private key; enter as a Render secret. Escaped `\\n` is normalized. |
| `AUTHORIZED_ADMIN_EMAIL` | Existing application admin allowlist identity. Must match the Cloudflare app's current allowlist. |
| `ADMIN_SESSION_SECRET` | Existing HMAC session secret, configured identically in Render and Cloudflare. |
| `AUTH_BACKEND_SHARED_SECRET` | New high-entropy service-to-service credential, configured in Render and Cloudflare. |
| `AUTH_RATE_LIMIT_MAX` | Optional per-process request limit; defaults to 60 per window. |
| `AUTH_RATE_LIMIT_WINDOW_MS` | Optional rate-limit window in milliseconds; defaults to 60000. |

`.env.example` contains placeholders only. Set actual credentials only in the
Render environment-variable UI or a protected local `.env` file (ignored by
Git). Never commit service-account JSON, private keys, `.env`, or `.env.local`.
The root Worker also needs `AUTH_BACKEND_URL` as a non-secret runtime variable
and `AUTH_BACKEND_SHARED_SECRET` as a Worker secret. Do not set Firebase Admin
credentials on the Worker for this split-auth design.

The root `.env.example` in the existing repository has previously been
identified as containing real values, so this backend change does not edit or
copy that file. Add the two Worker-side settings only to a clean placeholder
template after removing real values through a separate reviewed action.

## Independent GitHub repository

The parent repository ignores `/auth-backend/`; do not force-add it there. To
publish this folder independently, first create a new empty GitHub repository,
then run these commands after replacing the placeholders:

```sh
cd auth-backend
git init -b main
git add .
git status --short
git commit -m "Initial Render authentication backend"
git remote add origin https://github.com/<OWNER>/<REPOSITORY>.git
git push -u origin main
```

These commands are documentation only; no nested Git repository is initialized
and no commit or push is performed by this task.

## Render deployment

Create a **Web Service** from the new backend-only GitHub repository. Select
Node runtime, set the root directory to `.`, use Node `24.21.0`, build command
`npm ci && npm run build`, start command `npm start`, and health-check path
`/healthz`. Add each required environment variable from the table in Render's
Environment settings, then deploy. Do not configure the frontend Git repository
as this service's source, and do not attach a database or Sheets credentials.

Before directing Cloudflare to the service, check `/healthz` and `/readyz`, then
exercise `/auth/session` only through the Cloudflare BFF using dedicated test
accounts. Keep Cloudflare production DNS and the Vercel deployment unchanged
during staging. Store the service URL in Cloudflare as `AUTH_BACKEND_URL`.

The free Render web service spins down after inactivity and may take about a
minute to wake. An uptime monitor can reduce some idle periods but is not a
reliability guarantee and must not be part of authentication correctness. For
production admin login, choose an always-on paid instance sized after measuring
traffic; this project does not purchase or change a plan.

## Security, operation, and troubleshooting

- Firebase Admin verifies ID tokens and checks revocation. Project audience and
  issuer claims are checked against `FIREBASE_PROJECT_ID`.
- Only the configured admin email with a verified email may receive a session.
- The API accepts no browser CORS origins. `/auth/*` endpoints require the
  private service-to-service header. `/healthz` and `/readyz` reveal no settings.
- JSON requests are limited to 16 KiB, and authentication requests have an
  in-memory per-process rate limit. Keep Render's network access restricted
  where available; the shared secret remains required even if the URL is
  publicly reachable.
- Logs contain request ID, method, route, status, and duration only. Tokens,
  cookies, request bodies, credentials, and Firebase provider messages are not
  logged.
- A 401 `invalid_token` means Firebase rejected the ID token; 403
  `unauthorized` means the verified account is outside the admin allowlist;
  403 `email_unverified` means the authorized account has not verified its
  email; a 503 indicates configuration/provider/network failure. Match
  Cloudflare's request ID with Render logs.
- A Cloudflare 503 can also mean the URL or shared secret is missing, the
  service is cold-starting, times out, or returns an invalid response. Check
  only setting names/status and the sanitized request ID; never log the token.
- Logout clears the Cloudflare cookie. Stateless sessions have no server-side
  denylist; true immediate revocation would require a separately reviewed
  shared session store and is outside this change.

If any service-account credential was exposed, revoke it and issue a replacement
in Firebase Console, configure the replacement only in Render, and remove any
obsolete credential from the Worker after a controlled rollout. Rotate the
shared backend credential with an overlap procedure (accept old and new during
transition) if zero-downtime rotation is needed; this initial implementation
accepts one value at a time, so coordinate the Render and Worker update window.

## Safe deployment checklist

- [ ] Create a separate backend GitHub repository; verify no secrets are tracked.
- [ ] Configure dedicated Firebase Admin and session credentials in Render.
- [ ] Configure the exact same existing session-signing secret in Render and
      Cloudflare; configure a newly generated shared secret on both sides.
- [ ] Deploy Render and confirm `/healthz` and `/readyz`.
- [ ] Configure `AUTH_BACKEND_URL` and `AUTH_BACKEND_SHARED_SECRET` only on the
      intended Cloudflare environment.
- [ ] Test admin login with the authorized test account; confirm same-origin
      cookie flags and that the response body contains no session token.
- [ ] Verify admin APIs, logout, unavailable-backend handling, and Firebase
      revocation behavior without using production data or sending emails.
- [ ] Keep the existing Vercel deployment, production DNS, and production cron
      unchanged until a separately approved cutover.

# Exam Auth Service

One authentication service for both front ends:

| Portal key | Who | JWT audience | Access token | Session |
|---|---|---|---|---|
| `admin` | super_admin, college_admin, instructor | `exam-hub-admin` | 15 min | idle 12 h, max 7 days, many devices |
| `exam`  | student | `exam-portal` | 10 min | idle 2 h, max 8 h, **one device at a time** |

- **Access tokens:** RS256 JWTs (`typ: at+jwt`), signed with a **separate key per portal**. APIs verify them locally with the public keys from `/.well-known/jwks.json`, so they never see a private key.
- **Refresh tokens:** opaque, rotated on every use and stored only as SHA-256 hashes. Reusing an old refresh token signs the whole session out (theft detection).
- **Revocation:** log out, log out everywhere, sign out a specific device, change password (signs out other sessions), suspend the user (their next refresh fails).
- **Brute-force lockout:** after 5 wrong passwords per account, or 30 per IP, within 15 minutes.
- **Auditing:** every sign-in is written to `audit_logs`.
- **One user store:** it reads the existing `users`/`roles`/`user_roles` tables and only adds its own tables (`auth_sessions`, `auth_login_attempts`).

```
 React admin UI ──login/refresh──► exam-auth-service ◄──login/refresh── Student exam UI
        │                           (private keys)                           │
   Bearer token                     /.well-known/jwks.json              Bearer token
        ▼                                 │  public keys                     ▼
   exam-hub-api  ◄────────────────────────┴───────────────────────►  exam portal API
   (@exam-portal/auth-client,                                   (auth-client, introspect: true)
    audience exam-hub-admin)                                     audience exam-portal)
```

## 1. Setup

Requirements: Node.js 18.18+, PostgreSQL 13+, and the exam database (from `ddl_1.sql` / exam-hub-api).

```powershell
cd C:\CS_Exam_Portal_Work\exam-auth-service
npm install
copy .env.example .env          # set DATABASE_URL (same DB as exam-hub-api) and INTROSPECT_API_KEY
npm run db:migrate              # adds auth_sessions + auth_login_attempts
npm run keys:generate           # creates keys/admin/*.key.pem and keys/exam/*.key.pem
npm run dev                     # http://localhost:4001
```

Check: <http://localhost:4001/api/health> and <http://localhost:4001/.well-known/jwks.json>.

With the exam-hub-api demo data you can sign in as `admin@examhub.local` / `admin123` (admin portal) or `student1@examhub.local` / `student123` (exam portal).

> **Keys are secrets.** `keys/` is in `.gitignore` — back it up securely and never commit it. In development, missing keys are generated automatically on start; in production (`NODE_ENV=production`) the service refuses to start without them.

## 2. Endpoints

`:portal` is `admin` or `exam`. Every response has `Cache-Control: no-store`.

| Method | Path | Auth | Body / notes |
|---|---|---|---|
| POST | `/api/:portal/login` | – | `{ username, password }`. `username` is an email or phone number (formatting ignored). Returns `{ accessToken, expiresIn, refreshToken, refreshTokenExpiresAt, sessionId, user }` |
| POST | `/api/:portal/refresh` | – | `{ refreshToken }` (or the cookie). Returns a new access token and a **new** refresh token; the old one stops working |
| POST | `/api/:portal/logout` | – | `{ refreshToken }` or a Bearer access token. Always `200` |
| GET | `/api/:portal/me` | Bearer | Current user, session and token expiry |
| GET | `/api/:portal/sessions` | Bearer | The user's signed-in devices (`current: true` marks this one) |
| DELETE | `/api/:portal/sessions/:id` | Bearer | Sign out one of your devices |
| POST | `/api/:portal/logout-all` | Bearer | `{ keepCurrent?: false, allPortals?: false }` |
| POST | `/api/:portal/change-password` | Bearer | `{ currentPassword, newPassword }`. Signs out every other session |
| POST | `/api/introspect` | `x-api-key` | `{ token, portal? }` → `{ active: true, sub, sid, roles, college_id, … }` or `{ active: false }`. Service-to-service only |
| GET | `/.well-known/jwks.json` | – | Public signing keys (all portals) |
| GET | `/api/config` | – | Issuer, JWKS URL, audiences, lifetimes |
| GET | `/api/health` | – | DB + active key ids |

### Errors

Errors come back as `{ "error": { "message": "...", "details": { "reason": "..." } } }`.

| Status | `reason` values |
|---|---|
| **401** | `invalid_credentials`, `missing_token`, `token_expired`, `wrong_audience`, `bad_signature`, `session_revoked`, `already_rotated`, `token_reuse`, `expired`, `account_disabled` |
| **403** | `role_not_allowed` (e.g. a student on the admin portal), `account_disabled`, `account_not_activated`, `college_inactive` |
| **429** | `locked` (with a `Retry-After` header) |

### Access token claims

```json
{ "iss": "exam-auth-service", "aud": "exam-hub-admin", "sub": "<user id>", "sid": "<session id>",
  "jti": "…", "iat": 1789094454, "exp": 1789095354,
  "portal": "admin", "roles": ["college_admin"], "college_id": "<uuid>", "name": "Sarah Chen" }
```

`roles` only lists roles that are valid on that portal.

## 3. Protecting an API (authorize the token)

Install the client package into the API project:

```powershell
cd C:\CS_Exam_Portal_Work\exam-hub-api
npm install ..\exam-auth-service\packages\auth-client
```

```js
import { createAuthClient } from '@exam-portal/auth-client';

const auth = createAuthClient({ authUrl: 'http://localhost:4001', audience: 'exam-hub-admin' });

app.use('/api', auth.authenticate());                                    // valid admin-portal token required
router.post('/exams', auth.requireRoles('college_admin', 'instructor'), handler);
router.get('/colleges/:collegeId',
  auth.authorize((a, req) => a.hasRole('super_admin') || a.collegeId === req.params.collegeId), handler);
// handlers get req.auth = { userId, sessionId, roles, collegeId, name, portal, expiresAt, claims, hasRole() }
```

For the **student exam API**, add `introspect: true`. Each request, cached for 15 seconds, then asks the auth service whether the session is still active, so a second-device login or a suspension takes effect almost immediately:

```js
const auth = createAuthClient({
  authUrl: process.env.AUTH_URL, audience: 'exam-portal',
  introspect: true, introspectApiKey: process.env.AUTH_INTROSPECT_API_KEY,
});
app.use('/api', auth.authenticate(), auth.requireRoles('student'));
```

`examples/protected-api.js` is a runnable demo of both (`node examples/protected-api.js`, port 4002). More options are in `packages/auth-client/README.md`.

**Without introspection**, a revoked session's access token keeps working until it expires (at most 15 min for admin, 10 min for exam). Refreshing fails immediately. That is the usual trade-off for local JWT verification.

## 4. Front-end flow

1. **Sign in:** `POST /api/admin/login` (or `/api/exam/login`). Keep `accessToken` in memory, and `refreshToken` in storage (or use cookie mode below).
2. **Call APIs:** send `Authorization: Bearer <accessToken>`.
3. **Refresh:** on a `401` with `token_expired`, or shortly before `expiresAt`, call `/refresh` once. Replace **both** tokens with the new ones. If refresh fails, send the user to the login page.
4. **Sign out:** call `/logout` with the refresh token, then clear the stored tokens.

With two tabs open, let only one tab refresh at a time, for example with a shared promise. A second refresh with the same token within 15 seconds gets `already_rotated`. After 15 seconds it is treated as theft and the session is signed out.

**Cookie mode** (`REFRESH_TOKEN_COOKIE=true`): the refresh token is only sent as an `HttpOnly` cookie scoped to `/api/<portal>`, so page JavaScript can never read it. Call `refresh`/`logout` with `fetch(..., { credentials: 'include' })`. Use `COOKIE_SECURE=true` behind HTTPS. If the UI and the auth service are on different sites, you also need `COOKIE_SAMESITE=none`.

## 5. Key rotation

```powershell
npm run keys:rotate -- admin     # or: exam | all
npm run keys:list
# restart the service
```

The newest key signs new tokens. Older keys stay in the JWKS, so tokens they already signed keep working. The API clients pick up the new key automatically. Delete the old `.key.pem` file once its tokens have expired (after the access-token TTL), then restart.

## 6. Configuration

All settings are in `.env` (see `.env.example`):

| Setting | Variables |
|---|---|
| Token lifetimes, per portal | `ADMIN_ACCESS_TTL`, `ADMIN_REFRESH_IDLE_TTL`, `ADMIN_SESSION_MAX_TTL`, `EXAM_…` |
| Lockout | `LOGIN_MAX_FAILURES`, `LOGIN_MAX_FAILURES_PER_IP`, `LOGIN_WINDOW` |
| CORS | `CORS_ORIGIN` |
| Issuer | `AUTH_ISSUER` |
| Keys folder | `KEYS_DIR` |
| Introspection key | `INTROSPECT_API_KEY` |

To change which roles can use a portal, or to add a third portal, edit `src/config/portals.js`. To add a portal, also run `npm run keys:generate`.

## 7. Project layout

```
src/config/portals.js        portal definitions (audience, roles, lifetimes, single-session)
src/keys/keystore.js         loads RS256 keys, builds the JWKS
src/services/tokens.js       issue / verify access tokens
src/services/sessions.js     refresh-token sessions: create, rotate, reuse detection, revoke
src/services/loginGuard.js   lockout
src/services/users.js        user lookup (email/phone), role checks
src/routes/auth.routes.js    /api/:portal/* endpoints
src/routes/public.routes.js  jwks, config, health, introspect
packages/auth-client/        middleware for the portal APIs
db/migrations/               auth tables
scripts/                     migrate, keys
```

## 8. Notes

- exam-hub-api still has its own `/api/auth/login`. When you switch it to this service, replace its `authenticate` middleware with `auth.authenticate()` from the client. It can then load the user by `req.auth.userId`, and the old login route can be removed.
- The students roster (`students` table) has no login fields. Students sign in as `users` with the `student` role. If they should sign in with a roll number, that column needs adding to `users` (or a link from `students` to `users`).
- Forgot-password / reset links need an email or SMS provider. They are not included yet.

# @exam-portal/auth-client

Middleware for the portal APIs (exam-hub-api, the exam portal API) to accept tokens from **exam-auth-service**.

```bash
# from the API project folder
npm install ../exam-auth-service/packages/auth-client
```

```js
import { createAuthClient } from '@exam-portal/auth-client';

// Admin portal API
const auth = createAuthClient({ authUrl: process.env.AUTH_URL, audience: 'exam-hub-admin' });

app.use('/api', auth.authenticate());                                  // 401 without a valid admin token
router.post('/exams', auth.requireRoles('college_admin', 'instructor'), createExam);
router.get('/colleges/:collegeId', auth.authorize((a, req) => a.hasRole('super_admin') || a.collegeId === req.params.collegeId), getCollege);

// inside a handler
req.auth.userId; req.auth.roles; req.auth.collegeId; req.auth.sessionId;
```

```js
// Exam portal API: students only, and a sign-out / second-device login takes effect within seconds
const auth = createAuthClient({
  authUrl: process.env.AUTH_URL,
  audience: 'exam-portal',
  introspect: true,
  introspectApiKey: process.env.AUTH_INTROSPECT_API_KEY,
});
app.use('/api', auth.authenticate(), auth.requireRoles('student'));
```

| Option | Default | |
|---|---|---|
| `audience` | – | **required** — `exam-hub-admin` or `exam-portal` |
| `authUrl` | – | e.g. `http://localhost:4001` |
| `jwksUrl` | `${authUrl}/.well-known/jwks.json` | |
| `issuer` | `exam-auth-service` | must match `AUTH_ISSUER` of the service |
| `introspect` | `false` | also ask the service if the session is still active |
| `introspectApiKey` | – | the service's `INTROSPECT_API_KEY` |
| `introspectCacheSeconds` | `15` | how long an introspection answer is reused |
| `superRole` | `super_admin` | role that passes every `requireRoles` check (`null` to disable) |

Failures respond with JSON `{ "error": { "message", "reason" } }` — `401` (`missing_token`, `token_expired`, `wrong_audience`, `bad_signature`, `session_revoked`, …), `403` (`insufficient_role`) or `503` (`auth_unavailable`, introspection mode only). `auth.verify(token)` is also exported for WebSockets or jobs.

// Example: a tiny portal API protected by exam-auth-service.
// Run the auth service first, then:  node examples/protected-api.js
// (In your own API use: import { createAuthClient } from '@exam-portal/auth-client')
import express from 'express';
import { createAuthClient } from '../packages/auth-client/index.js';

const AUTH_URL = process.env.AUTH_URL || 'http://localhost:4001';

const adminAuth = createAuthClient({ authUrl: AUTH_URL, audience: 'exam-hub-admin' });
const examAuth = createAuthClient({
  authUrl: AUTH_URL,
  audience: 'exam-portal',
  introspect: !!process.env.INTROSPECT_API_KEY,
  introspectApiKey: process.env.INTROSPECT_API_KEY,
});

const app = express();

// ---- Admin portal API ----
const admin = express.Router();
admin.use(adminAuth.authenticate());
admin.get('/whoami', (req, res) => res.json({ userId: req.auth.userId, roles: req.auth.roles, collegeId: req.auth.collegeId }));
admin.post('/exams', adminAuth.requireRoles('college_admin', 'instructor'), (req, res) => res.status(201).json({ ok: true }));
admin.delete('/colleges/:id', adminAuth.requireRoles('super_admin'), (req, res) => res.json({ deleted: req.params.id }));
admin.get('/colleges/:collegeId/report',
  adminAuth.authorize((a, req) => a.hasRole('super_admin') || a.collegeId === req.params.collegeId),
  (req, res) => res.json({ report: 'ok' }));

// ---- Exam portal API ----
const exam = express.Router();
exam.use(examAuth.authenticate(), examAuth.requireRoles('student'));
exam.get('/my-exams', (req, res) => res.json({ student: req.auth.userId, exams: [] }));

app.use('/admin-api', admin);
app.use('/exam-api', exam);

const port = process.env.PORT || 4002;
app.listen(port, () => console.log(`example API on http://localhost:${port} (auth: ${AUTH_URL})`));

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { env } from './config/env.js';
import publicRoutes from './routes/public.routes.js';
import authRoutes from './routes/auth.routes.js';
import { errorHandler, notFoundHandler } from './middleware/error.js';

function isAllowedOrigin(origin) {
  if (!origin) return true;
  if (env.corsOrigins.includes('*') || env.corsOrigins.includes(origin)) return true;
  // In non-production environments, allow any localhost/127.0.0.1 port (e.g. Vite dynamic ports)
  if (!env.isProd && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;
  return false;
}

export function createApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
  app.use(cors({
    origin: (origin, cb) => cb(null, isAllowedOrigin(origin)),
    credentials: true, // needed for the optional refresh-token cookie
  }));
  app.use(express.json({ limit: '32kb' }));
  if (env.nodeEnv !== 'test') app.use(morgan(env.isProd ? 'combined' : 'dev'));

  // Tokens must never be cached by browsers or proxies
  app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

  app.use(publicRoutes);
  app.use('/api', authRoutes);

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

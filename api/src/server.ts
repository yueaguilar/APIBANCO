import 'dotenv/config';
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { SignJWT, jwtVerify } from 'jose';
import { Pool, type PoolClient } from 'pg';
import swaggerUi from 'swagger-ui-express';
import { z } from 'zod';

const scrypt = promisify(scryptCallback);
const env = z.object({
  DATABASE_URL: z.string().url(),
  SESSION_SECRET: z.string().min(32),
  PORT: z.coerce.number().int().positive().default(3000),
  PORTAL_ORIGIN: z.string().url().default('http://localhost:4200'),
  API_ORIGIN: z.string().url().default('http://localhost:3000'),
  NODE_ENV: z.string().default('development'),
}).parse(process.env);
const allowedBrowserOrigins = new Set([env.PORTAL_ORIGIN, env.API_ORIGIN]);

const pool = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined,
  max: 10,
});
const app = express();
const sessionKey = new TextEncoder().encode(env.SESSION_SECRET);
const roles = ['org_owner', 'org_admin', 'org_member', 'platform_admin'] as const;
type Role = typeof roles[number];
type Principal = { userId: string; organizationId: string | null; role: Role };
declare global {
  namespace Express {
    interface Request { principal?: Principal }
  }
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
const docsHelmet = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
});
const defaultHelmet = helmet();
app.use((req, res, next) => (req.path.startsWith('/docs') ? docsHelmet : defaultHelmet)(req, res, next));
app.use(cors({
  origin: env.PORTAL_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '16kb', strict: true }));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false }));
const authRateLimit = rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false });
app.use('/v1', (_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

const openApi = {
  openapi: '3.0.3',
  info: {
    title: 'BANCO KIKE API PLATFORM',
    version: '0.1.0',
    description: 'Portal y API de integraciones. Las operaciones bancarias reales no están habilitadas; use Sandbox.',
  },
  servers: [{ url: 'https://api.bancokike.com' }],
  paths: {
    '/health/live': { get: { summary: 'Estado del proceso', responses: { '200': { description: 'Proceso activo' } } } },
    '/health/ready': { get: { summary: 'Disponibilidad de la base de datos', responses: { '200': { description: 'Listo' }, '503': { description: 'No disponible' } } } },
    '/v1/organizations': {
      post: {
        summary: 'Registrar organización (estado pendiente)',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/OrganizationRegistration' } } },
        },
        responses: { '201': { description: 'Registro creado' }, '409': { description: 'Correo ya registrado' } },
      },
    },
    '/v1/auth/login': {
      post: {
        summary: 'Iniciar sesión de organización',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Login' } } },
        },
        responses: { '200': { description: 'Sesión creada en cookie HttpOnly' }, '401': { description: 'Credenciales inválidas' } },
      },
    },
    '/v1/me': { get: { summary: 'Consultar perfil de sesión', security: [{ sessionCookie: [] }], responses: { '200': { description: 'Perfil' }, '401': { description: 'No autenticado' } } } },
    '/v1/usage/summary': { get: { summary: 'Resumen de consumo de la organización', security: [{ sessionCookie: [] }], responses: { '200': { description: 'Consumo agregado' } } } },
    '/v1/applications': {
      get: { summary: 'Listar aplicaciones de la organización', security: [{ sessionCookie: [] }], responses: { '200': { description: 'Aplicaciones' } } },
      post: {
        summary: 'Registrar aplicación Sandbox',
        security: [{ sessionCookie: [] }],
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/ApplicationCreate' } } } },
        responses: { '201': { description: 'Aplicación creada' } },
      },
    },
    '/v1/applications/{id}/keys': {
      get: { summary: 'Listar metadatos de claves de la aplicación', security: [{ sessionCookie: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], responses: { '200': { description: 'Metadatos; nunca incluye el secreto' } } },
      post: {
        summary: 'Crear API key de Sandbox (se muestra una sola vez)',
        security: [{ sessionCookie: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        requestBody: { required: false, content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiKeyCreate' } } } },
        responses: { '201': { description: 'Credencial creada' } },
      },
    },
    '/v1/applications/{applicationId}/keys/{keyId}': { delete: { summary: 'Revocar API key', security: [{ sessionCookie: [] }], parameters: [{ name: 'applicationId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }, { name: 'keyId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], responses: { '204': { description: 'Clave revocada' } } } },
    '/v1/admin/organizations': { get: { summary: 'Listar organizaciones (solo administrador de plataforma)', security: [{ sessionCookie: [] }], responses: { '200': { description: 'Organizaciones' } } } },
    '/v1/admin/organizations/{id}/decision': {
      post: {
        summary: 'Aprobar, rechazar o suspender organización',
        security: [{ sessionCookie: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/OrganizationDecision' } } } },
        responses: { '200': { description: 'Estado actualizado' } },
      },
    },
    '/v1/admin/usage/summary': { get: { summary: 'Resumen global de consumo (solo administrador)', security: [{ sessionCookie: [] }], responses: { '200': { description: 'Consumo agregado' } } } },
    '/v1/integrations/ping': { post: { summary: 'Validar identificación de aplicación con API key', security: [{ bearerAuth: [] }], responses: { '200': { description: 'Identificación válida; Sandbox' }, '401': { description: 'Credencial inválida' } } } },
  },
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer' },
      sessionCookie: { type: 'apiKey', in: 'cookie', name: 'bk_session' },
    },
    schemas: {
      OrganizationRegistration: {
        type: 'object',
        required: ['organizationName', 'email', 'password'],
        properties: {
          organizationName: { type: 'string', minLength: 2, maxLength: 160 },
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 12, maxLength: 128 },
        },
      },
      Login: {
        type: 'object',
        required: ['email', 'password'],
        properties: { email: { type: 'string', format: 'email' }, password: { type: 'string' } },
      },
      ApplicationCreate: {
        type: 'object',
        required: ['name'],
        properties: { name: { type: 'string', minLength: 2, maxLength: 120 }, environment: { type: 'string', enum: ['sandbox'] } },
      },
      ApiKeyCreate: {
        type: 'object',
        properties: { expiresAt: { type: 'string', format: 'date-time' } },
      },
      OrganizationDecision: {
        type: 'object',
        required: ['status'],
        properties: { status: { type: 'string', enum: ['active', 'rejected', 'suspended'] } },
      },
    },
  },
};
app.use('/docs', swaggerUi.serve, swaggerUi.setup(openApi));
app.get('/openapi.json', (_req, res) => res.json(openApi));
app.get('/health/live', (_req, res) => res.json({ status: 'ok' }));
app.get('/health/ready', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ready' });
  } catch {
    res.status(503).json({ status: 'unavailable' });
  }
});

function parseCookies(header = ''): Record<string, string> {
  return Object.fromEntries(header.split(';').map((part) => {
    const index = part.indexOf('=');
    if (index < 0) return ['', ''];
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try { return [key, decodeURIComponent(value)]; }
    catch { return [key, value]; }
  }).filter(([key]) => key));
}

function requireSameOrigin(req: Request, res: Response, next: NextFunction) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const hasSession = Boolean(parseCookies(req.headers.cookie).bk_session);
    const origin = req.get('origin');
    const invalidBody = req.method !== 'DELETE' && !req.is('application/json');
    if (invalidBody || (origin && !allowedBrowserOrigins.has(origin)) || (hasSession && !origin)) {
      return res.status(403).json({ error: 'origin_not_allowed' });
    }
  }
  next();
}
app.use('/v1', requireSameOrigin);

async function issueSession(principal: Principal): Promise<string> {
  return new SignJWT({ sub: principal.userId, org: principal.organizationId, role: principal.role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('8h')
    .sign(sessionKey);
}

function setSessionCookie(res: Response, token: string) {
  res.cookie('bk_session', token, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 8 * 60 * 60 * 1000,
  });
}

async function requireSession(req: Request, res: Response, next: NextFunction) {
  try {
    const token = parseCookies(req.headers.cookie).bk_session;
    if (!token) return res.status(401).json({ error: 'authentication_required' });
    let payload;
    try {
      ({ payload } = await jwtVerify(token, sessionKey, { algorithms: ['HS256'] }));
    } catch {
      return res.status(401).json({ error: 'invalid_session' });
    }
    if (typeof payload.sub !== 'string') return res.status(401).json({ error: 'invalid_session' });
    const result = await withAuthLookup((client) => client.query(
      `SELECT u.id, u.organization_id, u.role, u.active,
              o.status AS organization_status
       FROM users u LEFT JOIN organizations o ON o.id = u.organization_id
       WHERE u.id = $1`,
      [payload.sub],
    ));
    const user = result.rows[0];
    if (!user?.active || !roles.includes(user.role as Role)) return res.status(401).json({ error: 'invalid_session' });
    if (user.organization_id && user.organization_status !== 'active') {
      return res.status(403).json({ error: 'organization_not_active', status: user.organization_status });
    }
    req.principal = { userId: user.id, organizationId: user.organization_id, role: user.role };
    next();
  } catch (error) {
    if (error instanceof Error && error.name === 'JWTExpired') return res.status(401).json({ error: 'session_expired' });
    next(error);
  }
}

function requireOrganizationAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.principal?.organizationId || !['org_owner', 'org_admin'].includes(req.principal.role)) {
    return res.status(403).json({ error: 'insufficient_permissions' });
  }
  next();
}

function requirePlatformAdmin(req: Request, res: Response, next: NextFunction) {
  if (req.principal?.role !== 'platform_admin') return res.status(403).json({ error: 'insufficient_permissions' });
  next();
}

async function withTenant<T>(organizationId: string, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.organization_id', $1, true)`, [organizationId]);
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function withPlatform<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.platform_admin', 'true', true)`);
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function withAuthLookup<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.auth_lookup', 'true', true)`);
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function audit(client: PoolClient, organizationId: string | null, actorId: string | null, eventType: string, metadata: object = {}) {
  await client.query(
    `INSERT INTO audit_events (organization_id, actor_user_id, event_type, metadata)
     VALUES ($1, $2, $3, $4::jsonb)`,
    [organizationId, actorId, eventType, JSON.stringify(metadata)],
  );
}

const registrationSchema = z.object({
  organizationName: z.string().trim().min(2).max(160),
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  password: z.string().min(12).max(128),
});

app.post('/v1/organizations', authRateLimit, async (req, res, next) => {
  try {
    const input = registrationSchema.parse(req.body);
    const salt = randomBytes(16);
    const passwordHash = (await scrypt(input.password, salt, 64)) as Buffer;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('app.registration', 'true', true)`);
      const organizationId = randomUUID();
      await client.query(
        `INSERT INTO organizations (id, name, status) VALUES ($1, $2, 'pending')`,
        [organizationId, input.organizationName],
      );
      await client.query(`SELECT set_config('app.organization_id', $1, true)`, [organizationId]);
      const user = await client.query(
        `INSERT INTO users (organization_id, email, password_hash, password_salt, role)
         VALUES ($1, $2, $3, $4, 'org_owner') RETURNING id`,
        [organizationId, input.email, passwordHash, salt],
      );
      await audit(client, organizationId, user.rows[0].id, 'organization.registered');
      await client.query('COMMIT');
      res.status(201).json({ organizationId, status: 'pending_approval' });
    } catch (error) {
      await client.query('ROLLBACK');
      if ((error as { code?: string }).code === '23505') return res.status(409).json({ error: 'email_already_registered' });
      throw error;
    } finally {
      client.release();
    }
  } catch (error) { next(error); }
});

app.post('/v1/auth/login', authRateLimit, async (req, res, next) => {
  try {
    const input = z.object({ email: z.string().email().max(254).transform((value) => value.toLowerCase()), password: z.string().min(1).max(128) }).parse(req.body);
    const result = await withAuthLookup((client) => client.query(
      `SELECT u.id, u.organization_id, u.password_hash, u.password_salt, u.role, u.active,
              o.status AS organization_status
       FROM users u LEFT JOIN organizations o ON o.id = u.organization_id
       WHERE u.email = $1`,
      [input.email],
    ));
    const user = result.rows[0];
    if (!user?.active || !user.password_hash || !user.password_salt) return res.status(401).json({ error: 'invalid_credentials' });
    const candidate = (await scrypt(input.password, user.password_salt, 64)) as Buffer;
    if (candidate.length !== user.password_hash.length || !timingSafeEqual(candidate, user.password_hash)) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    if (user.organization_status !== 'active' && user.role !== 'platform_admin') {
      return res.status(403).json({ error: 'organization_not_approved', status: user.organization_status });
    }
    const token = await issueSession({ userId: user.id, organizationId: user.organization_id, role: user.role });
    setSessionCookie(res, token);
    res.json({ authenticated: true });
  } catch (error) { next(error); }
});

app.post('/v1/auth/logout', (_req, res) => {
  res.clearCookie('bk_session', { httpOnly: true, secure: env.NODE_ENV === 'production', sameSite: 'strict', path: '/' });
  res.status(204).end();
});
app.get('/v1/me', requireSession, async (req, res, next) => {
  try {
    const { principal } = req;
    if (!principal) return res.status(401).json({ error: 'authentication_required' });
    if (!principal.organizationId) return res.json({ role: principal.role });
    const result = await withTenant(principal.organizationId, (client) => client.query(
      `SELECT o.id, o.name, o.status, u.email, u.role
       FROM organizations o JOIN users u ON u.organization_id = o.id
       WHERE o.id = $1 AND u.id = $2`,
      [principal.organizationId, principal.userId],
    ));
    res.json(result.rows[0]);
  } catch (error) { next(error); }
});

app.get('/v1/usage/summary', requireSession, async (req, res, next) => {
  try {
    const orgId = req.principal?.organizationId;
    if (!orgId) return res.status(403).json({ error: 'organization_required' });
    const result = await withTenant(orgId, (client) => client.query(
      `SELECT
         count(*) FILTER (WHERE created_at >= date_trunc('day', now()))::int AS today,
         count(*) FILTER (WHERE created_at >= now() - interval '7 days')::int AS last_7_days,
         count(*) FILTER (WHERE created_at >= date_trunc('month', now()))::int AS this_month,
         count(*) FILTER (WHERE status_code >= 400)::int AS errors
       FROM api_request_logs WHERE organization_id = $1`,
      [orgId],
    ));
    res.json(result.rows[0]);
  } catch (error) { next(error); }
});

app.get('/v1/applications', requireSession, async (req, res, next) => {
  try {
    const orgId = req.principal?.organizationId;
    if (!orgId) return res.status(403).json({ error: 'organization_required' });
    const result = await withTenant(orgId, (client) => client.query(
      `SELECT id, name, environment, created_at FROM applications
       WHERE organization_id = $1 ORDER BY created_at DESC`,
      [orgId],
    ));
    res.json({ applications: result.rows });
  } catch (error) { next(error); }
});

app.get('/v1/applications/:id/keys', requireSession, requireOrganizationAdmin, async (req, res, next) => {
  try {
    const orgId = req.principal!.organizationId!;
    const result = await withTenant(orgId, (client) => client.query(
      `SELECT id, public_id, created_at, expires_at, revoked_at, last_used_at
       FROM api_keys WHERE application_id = $1 AND organization_id = $2
       ORDER BY created_at DESC`,
      [req.params.id, orgId],
    ));
    res.json({ keys: result.rows });
  } catch (error) { next(error); }
});

app.post('/v1/applications', requireSession, requireOrganizationAdmin, async (req, res, next) => {
  try {
    const input = z.object({
      name: z.string().trim().min(2).max(120),
      environment: z.enum(['sandbox', 'production']).default('sandbox'),
    }).parse(req.body);
    if (input.environment === 'production') return res.status(403).json({ error: 'production_not_enabled' });
    const principal = req.principal!;
    const result = await withTenant(principal.organizationId!, async (client) => {
      const created = await client.query(
        `INSERT INTO applications (organization_id, name, environment)
         SELECT $1, $2, 'sandbox' FROM organizations WHERE id = $1 AND status = 'active'
         RETURNING id, name, environment, created_at`,
        [principal.organizationId, input.name],
      );
      if (!created.rowCount) throw Object.assign(new Error('organization_not_approved'), { status: 403 });
      await audit(client, principal.organizationId, principal.userId, 'application.created', { applicationId: created.rows[0].id });
      return created.rows[0];
    });
    res.status(201).json(result);
  } catch (error) { next(error); }
});

app.post('/v1/applications/:id/keys', requireSession, requireOrganizationAdmin, async (req, res, next) => {
  try {
    const { expiresAt } = z.object({ expiresAt: z.iso.datetime().optional() }).parse(req.body ?? {});
    if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
      return res.status(400).json({ error: 'expiration_must_be_in_future' });
    }
    const principal = req.principal!;
    const keyId = randomBytes(12).toString('hex');
    const secret = randomBytes(32).toString('base64url');
    const apiKey = `bk_sandbox_${keyId}.${secret}`;
    const keyHash = createHash('sha256').update(apiKey).digest();
    const created = await withTenant(principal.organizationId!, async (client) => {
      const key = await client.query(
        `INSERT INTO api_keys (organization_id, application_id, public_id, secret_hash, expires_at)
         SELECT $1, a.id, $2, $3, $5 FROM applications a
         JOIN organizations o ON o.id = a.organization_id
         WHERE a.id = $4 AND a.organization_id = $1 AND a.environment = 'sandbox' AND o.status = 'active'
         RETURNING id, public_id, created_at, expires_at`,
        [principal.organizationId, keyId, keyHash, req.params.id, expiresAt ?? null],
      );
      if (!key.rowCount) throw Object.assign(new Error('application_not_found_or_unavailable'), { status: 404 });
      await audit(client, principal.organizationId, principal.userId, 'api_key.created', { keyId: key.rows[0].id });
      return key.rows[0];
    });
    res.status(201).json({ ...created, key: apiKey, warning: 'Copy this key now. It cannot be retrieved again.' });
  } catch (error) { next(error); }
});

app.delete('/v1/applications/:applicationId/keys/:keyId', requireSession, requireOrganizationAdmin, async (req, res, next) => {
  try {
    const principal = req.principal!;
    await withTenant(principal.organizationId!, async (client) => {
      const revoked = await client.query(
        `UPDATE api_keys SET revoked_at = now()
         WHERE id = $1 AND application_id = $2 AND organization_id = $3 AND revoked_at IS NULL
         RETURNING id`,
        [req.params.keyId, req.params.applicationId, principal.organizationId],
      );
      if (!revoked.rowCount) throw Object.assign(new Error('key_not_found'), { status: 404 });
      await audit(client, principal.organizationId, principal.userId, 'api_key.revoked', { keyId: req.params.keyId });
    });
    res.status(204).end();
  } catch (error) { next(error); }
});

app.get('/v1/admin/organizations', requireSession, requirePlatformAdmin, async (_req, res, next) => {
  try {
    const result = await withPlatform((client) => client.query(
      `SELECT o.id, o.name, o.status, o.created_at, count(DISTINCT u.id)::int AS member_count,
              count(DISTINCT a.id)::int AS application_count
       FROM organizations o
       LEFT JOIN users u ON u.organization_id = o.id
       LEFT JOIN applications a ON a.organization_id = o.id
       GROUP BY o.id ORDER BY o.created_at DESC`,
    ));
    res.json({ organizations: result.rows });
  } catch (error) { next(error); }
});

app.get('/v1/admin/usage/summary', requireSession, requirePlatformAdmin, async (_req, res, next) => {
  try {
    const result = await withPlatform((client) => client.query(
      `SELECT
         count(*) FILTER (WHERE created_at >= date_trunc('day', now()))::int AS today,
         count(*) FILTER (WHERE created_at >= now() - interval '7 days')::int AS last_7_days,
         count(*) FILTER (WHERE created_at >= date_trunc('month', now()))::int AS this_month,
         count(*) FILTER (WHERE status_code >= 400)::int AS errors
       FROM api_request_logs`,
    ));
    res.json(result.rows[0]);
  } catch (error) { next(error); }
});

app.post('/v1/admin/organizations/:id/decision', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const { status } = z.object({ status: z.enum(['active', 'rejected', 'suspended']) }).parse(req.body);
    const principal = req.principal!;
    await withPlatform(async (client) => {
      const updated = await client.query(
        `UPDATE organizations SET status = $1, updated_at = now()
         WHERE id = $2 RETURNING id, name, status`,
        [status, req.params.id],
      );
      if (!updated.rowCount) throw Object.assign(new Error('organization_not_found'), { status: 404 });
      await client.query(`SELECT set_config('app.organization_id', $1, true)`, [updated.rows[0].id]);
      await audit(client, updated.rows[0].id, principal.userId, `organization.${status}`);
      return updated.rows[0];
    }).then((organization) => res.json(organization));
  } catch (error) { next(error); }
});

app.post('/v1/integrations/ping', async (req, res, next) => {
  const requestStartedAt = Date.now();
  try {
    const authorization = req.get('authorization') ?? '';
    const match = /^Bearer (bk_sandbox_[a-f0-9]{24}\.[A-Za-z0-9_-]{43})$/.exec(authorization);
    if (!match) return res.status(401).json({ error: 'invalid_api_key' });
    const digest = createHash('sha256').update(match[1]).digest();
    const result = await pool.connect().then(async (client) => {
      try {
        await client.query('BEGIN');
        await client.query(`SELECT set_config('app.key_auth', 'true', true)`);
        const key = await client.query(
          `UPDATE api_keys k SET last_used_at = now()
           FROM organizations o
           WHERE k.secret_hash = $1 AND k.revoked_at IS NULL
             AND (k.expires_at IS NULL OR k.expires_at > now())
             AND k.organization_id = o.id AND o.status = 'active'
           RETURNING k.public_id, k.organization_id, k.application_id`,
          [digest],
        );
        await client.query('COMMIT');
        return key;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    });
    if (!result.rowCount) return res.status(401).json({ error: 'invalid_api_key' });
    await withTenant(result.rows[0].organization_id, (client) => client.query(
      `INSERT INTO api_request_logs
       (organization_id, application_id, endpoint, method, status_code, duration_ms, origin_domain)
       VALUES ($1, $2, '/v1/integrations/ping', 'POST', 200, $3, $4)`,
      [
        result.rows[0].organization_id,
        result.rows[0].application_id,
        Date.now() - requestStartedAt,
        (() => {
          try { return req.get('origin') ? new URL(req.get('origin')!).hostname : null; }
          catch { return null; }
        })(),
      ],
    ));
    res.json({ authenticated: true, environment: 'sandbox', message: 'Identificación de aplicación válida. Sin acceso a operaciones bancarias.' });
  } catch (error) { next(error); }
});

const errorHandler: express.ErrorRequestHandler = (error, _req, res, _next) => {
  if (error instanceof z.ZodError) {
    const details = error.issues.map(({ code, path, message }) => ({ code, path, message }));
    return res.status(400).json({ error: 'validation_error', details });
  }
  const status = Number((error as { status?: number }).status) || 500;
  if (status >= 500) console.error('Request failed', error instanceof Error ? error.name : 'UnknownError');
  res.status(status).json({ error: status >= 500 ? 'internal_error' : (error as Error).message });
};
app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
app.use(errorHandler);

const server = app.listen(env.PORT, () => console.log(`API listening on port ${env.PORT}`));
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => server.close(async () => {
    await pool.end();
    process.exit(0);
  }));
}

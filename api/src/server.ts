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
  PORTAL_ORIGIN: z.string().url().optional(),
  API_ORIGIN: z.string().url().default('http://localhost:3000'),
  NODE_ENV: z.string().default('development'),
}).parse(process.env);
const configuredPortalOrigin = env.PORTAL_ORIGIN
  ?? (env.NODE_ENV === 'production' ? 'https://apibanco-e3112.web.app' : 'http://localhost:4200');
const firebasePortalOrigin = 'https://apibanco-e3112.web.app';
const firebasePortalHostname = new URL(firebasePortalOrigin).hostname;
const pairedFirebaseAppOrigin = firebasePortalHostname.endsWith('.web.app')
  ? `https://${firebasePortalHostname.replace(/\.web\.app$/, '.firebaseapp.com')}`
  : undefined;
const localPortalOrigins = env.NODE_ENV === 'production'
  ? []
  : ['http://localhost:4200', 'http://127.0.0.1:4200'];
const allowedBrowserOrigins = new Set([
  new URL(configuredPortalOrigin).origin,
  ...localPortalOrigins,
  firebasePortalOrigin,
  ...(pairedFirebaseAppOrigin ? [pairedFirebaseAppOrigin] : []),
  new URL(env.API_ORIGIN).origin,
]);
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => callback(null, !origin || allowedBrowserOrigins.has(origin)),
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

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
app.use(cors(corsOptions));
const docsHelmet = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', firebasePortalOrigin],
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
  servers: [{ url: env.API_ORIGIN }],
  paths: {
    '/health/live': { get: { summary: 'Estado del proceso', responses: { '200': { description: 'Proceso activo' } } } },
    '/health/ready': { get: { summary: 'Disponibilidad de la base de datos y esquema requerido', responses: { '200': { description: 'Listo' }, '503': { description: 'Base de datos no disponible o requiere migraciones' } } } },
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
    '/v1/admin/users': { get: { summary: 'Listar usuarios con búsqueda y paginación (solo administrador de plataforma)', security: [{ sessionCookie: [] }], parameters: [{ name: 'page', in: 'query', schema: { type: 'integer', minimum: 1 } }, { name: 'pageSize', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 100 } }, { name: 'search', in: 'query', schema: { type: 'string' } }, { name: 'organizationId', in: 'query', schema: { type: 'string', format: 'uuid' } }, { name: 'role', in: 'query', schema: { type: 'string', enum: ['org_owner', 'org_admin', 'org_member', 'platform_admin'] } }, { name: 'active', in: 'query', schema: { type: 'boolean' } }], responses: { '200': { description: 'Usuarios y total de resultados' } } } },
    '/v1/admin/users/{id}': { get: { summary: 'Consultar usuario (solo administrador de plataforma)', security: [{ sessionCookie: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], responses: { '200': { description: 'Usuario' }, '404': { description: 'Usuario no encontrado' } } } },
    '/v1/admin/users/{id}/role': {
      patch: {
        summary: 'Modificar rol de usuario (solo administrador de plataforma)',
        security: [{ sessionCookie: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/UserRoleUpdate' } } } },
        responses: {
          '200': { description: 'Rol actualizado' },
          '400': { description: 'Rol u organización inválida' },
          '403': { description: 'No permitido o último administrador global' },
          '409': { description: 'Debe mantenerse al menos un administrador global activo' },
        },
      },
    },
    '/v1/admin/users/{id}/status': { patch: { summary: 'Activar o desactivar cuenta (solo administrador de plataforma)', security: [{ sessionCookie: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/UserStatusUpdate' } } } }, responses: { '200': { description: 'Estado actualizado' }, '403': { description: 'No permitido o último administrador global' } } } },
    '/v1/admin/roles': { get: { summary: 'Consultar roles y alcance (solo administrador de plataforma)', security: [{ sessionCookie: [] }], responses: { '200': { description: 'Roles disponibles' } } } },
    '/v1/admin/audit-logs': { get: { summary: 'Consultar historial de cambios de usuarios y roles (solo administrador de plataforma)', security: [{ sessionCookie: [] }], parameters: [{ name: 'page', in: 'query', schema: { type: 'integer', minimum: 1 } }, { name: 'pageSize', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 100 } }], responses: { '200': { description: 'Historial paginado' } } } },
    '/v1/admin/organizations/{id}/applications': { get: { summary: 'Listar aplicaciones y metadatos de claves de una organización', security: [{ sessionCookie: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], responses: { '200': { description: 'Aplicaciones, acceso API y metadatos de claves; nunca incluye secretos' } } } },
    '/v1/admin/organizations/{id}/api-access': { post: { summary: 'Habilitar o deshabilitar el acceso API de una organización', security: [{ sessionCookie: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiAccessDecision' } } } }, responses: { '200': { description: 'Acceso actualizado' } } } },
    '/v1/admin/applications/{id}/api-access': { post: { summary: 'Habilitar o deshabilitar el acceso API de una aplicación', security: [{ sessionCookie: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiAccessDecision' } } } }, responses: { '200': { description: 'Acceso actualizado' } } } },
    '/v1/admin/organizations/{organizationId}/applications/{applicationId}/keys/{keyId}': { delete: { summary: 'Revocar API key de una organización (solo metadatos)', security: [{ sessionCookie: [] }], parameters: [{ name: 'organizationId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }, { name: 'applicationId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }, { name: 'keyId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }], responses: { '204': { description: 'Clave revocada' }, '404': { description: 'Clave no encontrada o ya revocada' } } } },
    '/v1/admin/organizations/{id}/decision': {
      post: {
        summary: 'Aprobar, rechazar o suspender organización',
        security: [{ sessionCookie: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/OrganizationDecision' } } } },
        responses: { '200': { description: 'Estado actualizado' } },
      },
    },
    '/v1/admin/usage/summary': { get: { summary: 'Resumen global y últimas 50 solicitudes de integración (solo administrador)', security: [{ sessionCookie: [] }], responses: { '200': { description: 'Consumo agregado y solicitudes registradas con organización, aplicación, dominio de origen y endpoint' } } } },
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
          fullName: { type: 'string', maxLength: 120 },
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
      ApiAccessDecision: {
        type: 'object',
        required: ['enabled'],
        properties: { enabled: { type: 'boolean' } },
      },
      UserRoleUpdate: {
        type: 'object',
        required: ['role'],
        properties: {
          role: { type: 'string', enum: ['org_owner', 'org_admin', 'org_member', 'platform_admin'] },
          organizationId: { type: 'string', format: 'uuid', nullable: true },
        },
      },
      UserStatusUpdate: {
        type: 'object',
        required: ['active'],
        properties: { active: { type: 'boolean' } },
      },
    },
  },
};
const swaggerCustomCss = `
  html, body {
    min-width: 320px;
    background:
      radial-gradient(ellipse at 12% 0%, rgba(32, 113, 142, .2), transparent 34rem),
      radial-gradient(ellipse at 88% 26%, rgba(20, 72, 106, .18), transparent 32rem),
      linear-gradient(135deg, #081a2d, #0d1b2a);
    color: #edf9ff;
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  .swagger-ui { color: #edf9ff; font-family: inherit; }
  .swagger-ui .topbar {
    padding: 10px 0;
    border-bottom: 1px solid rgba(255, 255, 255, .18);
    background: rgba(8, 26, 45, .88);
  }
  .swagger-ui .topbar .wrapper { max-width: 1180px; }
  .swagger-ui .topbar-wrapper .link { display: block; width: 190px; height: 56px; font-size: 0; }
  .swagger-ui .topbar-wrapper .link svg { display: none; }
  .swagger-ui .topbar-wrapper .link::before {
    display: block;
    width: 190px;
    height: 56px;
    background: url("${firebasePortalOrigin}/logo.ico") center / contain no-repeat;
    content: "";
  }
  .swagger-ui .information-container, .swagger-ui .scheme-container {
    border-color: rgba(255, 255, 255, .12);
    background: transparent;
    box-shadow: none;
  }
  .swagger-ui .info, .swagger-ui .info .title, .swagger-ui .info p,
  .swagger-ui .info li, .swagger-ui .info a, .swagger-ui .opblock-tag,
  .swagger-ui .opblock-tag small, .swagger-ui .servers-title,
  .swagger-ui label, .swagger-ui .parameter__name, .swagger-ui .parameter__type,
  .swagger-ui table thead tr th, .swagger-ui table tbody tr td,
  .swagger-ui .response-col_status, .swagger-ui .response-col_description,
  .swagger-ui .model-title, .swagger-ui section.models h4,
  .swagger-ui .model, .swagger-ui .model-toggle, .swagger-ui .prop-type,
  .swagger-ui .prop-format, .swagger-ui .renderedMarkdown p {
    color: #edf9ff;
  }
  .swagger-ui .info .title { color: #c9f6ff; }
  .swagger-ui .info a, .swagger-ui .renderedMarkdown a { color: #90e0ef; }
  .swagger-ui .opblock-tag { border-bottom-color: rgba(255, 255, 255, .18); }
  .swagger-ui .opblock-tag:hover { background: rgba(255, 255, 255, .04); }
  .swagger-ui .opblock .opblock-summary {
    border-color: rgba(255, 255, 255, .12);
    background: rgba(255, 255, 255, .045);
  }
  .swagger-ui .opblock .opblock-summary-description,
  .swagger-ui .opblock .opblock-summary-path,
  .swagger-ui .opblock .opblock-summary-method { color: #edf9ff; }
  .swagger-ui .opblock .opblock-section-header,
  .swagger-ui .responses-wrapper,
  .swagger-ui .parameters-container,
  .swagger-ui .model-box, .swagger-ui .highlight-code,
  .swagger-ui .microlight, .swagger-ui .tab li,
  .swagger-ui .response-control-media-type__accept-header {
    border-color: rgba(255, 255, 255, .12);
    background: rgba(3, 14, 26, .38);
    color: #edf9ff;
  }
  .swagger-ui .opblock .opblock-section-header h4,
  .swagger-ui .opblock .opblock-section-header label,
  .swagger-ui .tab li, .swagger-ui .response-control-media-type__accept-header {
    color: #b9d3df;
  }
  .swagger-ui input, .swagger-ui select, .swagger-ui textarea {
    border-color: rgba(255, 255, 255, .2);
    background: rgba(3, 14, 26, .55);
    color: #edf9ff;
  }
  .swagger-ui select option { background: #0d1b2a; color: #edf9ff; }
  .swagger-ui .btn {
    border-color: rgba(144, 224, 239, .32);
    color: #c9f6ff;
  }
  .swagger-ui .btn.execute {
    border-color: rgba(201, 246, 255, .35);
    background: linear-gradient(135deg, rgba(144, 224, 239, .34), rgba(62, 153, 177, .24));
    color: #c9f6ff;
  }
  .swagger-ui .btn.cancel { border-color: rgba(255, 140, 168, .4); color: #ff8ca8; }
  .swagger-ui .authorization__btn svg, .swagger-ui .expand-operation svg,
  .swagger-ui .expand-methods svg, .swagger-ui .opblock-control-arrow {
    fill: #90e0ef;
  }
  .swagger-ui .responses-inner h4, .swagger-ui .responses-inner h5 { color: #c9f6ff; }
  .swagger-ui .response pre, .swagger-ui .curl-command, .swagger-ui .copy-to-clipboard {
    background: rgba(3, 14, 26, .6);
    color: #edf9ff;
  }
  .swagger-ui .dialog-ux .modal-ux {
    border-color: rgba(255, 255, 255, .18);
    background: #0d1b2a;
    color: #edf9ff;
  }
  .swagger-ui .dialog-ux .modal-ux-header h3 { color: #c9f6ff; }
  @media (max-width: 600px) {
    .swagger-ui .topbar .wrapper { padding: 0 16px; }
    .swagger-ui .info { margin: 24px 16px; }
  }
`;
app.use('/docs', swaggerUi.serve, swaggerUi.setup(openApi, {
  customCss: swaggerCustomCss,
  customSiteTitle: 'BANCO KIKE API PLATFORM | Documentación',
  customfavIcon: `${firebasePortalOrigin}/logo.ico`,
}));
app.get('/openapi.json', (_req, res) => res.json(openApi));
app.get('/health/live', (_req, res) => res.json({ status: 'ok' }));
app.get('/health/ready', async (_req, res) => {
  try {
    const result = await pool.query<{
      organization_api_enabled: boolean;
      application_api_enabled: boolean;
      user_full_name: boolean;
      user_audit: boolean;
    }>(
      `SELECT
         EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = current_schema()
             AND table_name = 'organizations' AND column_name = 'api_enabled'
         ) AS organization_api_enabled,
         EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = current_schema()
             AND table_name = 'applications' AND column_name = 'api_enabled'
         ) AS application_api_enabled,
         EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = current_schema()
             AND table_name = 'users' AND column_name = 'full_name'
         ) AS user_full_name,
         to_regclass(current_schema() || '.admin_user_audit') IS NOT NULL AS user_audit`,
    );
    const schema = result.rows[0];
    const requiredMigrations = [
      ...(!schema.organization_api_enabled || !schema.application_api_enabled ? ['002_admin_api_access.sql'] : []),
      ...(!schema.user_full_name || !schema.user_audit ? ['003_admin_user_management.sql'] : []),
    ];
    if (requiredMigrations.length) {
      return res.status(503).json({
        status: 'unavailable',
        error: 'database_schema_outdated',
        requiredMigrations,
      });
    }
    res.json({ status: 'ready' });
  } catch {
    res.status(503).json({ status: 'unavailable', error: 'database_unavailable' });
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
    sameSite: env.NODE_ENV === 'production' ? 'none' : 'strict',
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

async function auditAdminUserChange(
  client: PoolClient,
  input: {
    actorId: string;
    targetId: string;
    organizationId: string | null;
    action: 'role_changed' | 'account_status_changed';
    previousRole: Role;
    newRole: Role;
    previousActive: boolean;
    newActive: boolean;
    outcome: 'success' | 'rejected';
  },
) {
  await client.query(
    `INSERT INTO admin_user_audit
       (actor_user_id, target_user_id, organization_id, action, previous_role, new_role,
        previous_active, new_active, outcome)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      input.actorId,
      input.targetId,
      input.organizationId,
      input.action,
      input.previousRole,
      input.newRole,
      input.previousActive,
      input.newActive,
      input.outcome,
    ],
  );
}

const registrationSchema = z.object({
  organizationName: z.string().trim().min(2).max(160),
  fullName: z.string().trim().max(120).optional().transform((value) => value || null),
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  password: z.string().min(12).max(128),
});

function postgresErrorFields(error: unknown) {
  const details = error instanceof Error
    ? error as Error & {
      code?: string;
      schema?: string;
      table?: string;
      column?: string;
      constraint?: string;
      detail?: string;
    }
    : undefined;
  const redact = (value: string | undefined) => value
    ?.replace(/(password(?:_hash|_salt)?|session_secret|database_url|cookie|token)\s*([=:])\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1$2[REDACTED]')
    .replace(/(postgres(?:ql)?:\/\/)[^/\s@]+@/gi, '$1[REDACTED]@');

  return {
    name: redact(details?.name) ?? 'UnknownError',
    message: redact(details?.message) ?? 'Unknown error',
    code: redact(details?.code),
    schema: redact(details?.schema),
    table: redact(details?.table),
    column: redact(details?.column),
    constraint: redact(details?.constraint),
    detail: redact(details?.detail),
  };
}

function isDuplicateUserEmail(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const databaseError = error as Error & { code?: string; table?: string; constraint?: string };
  return databaseError.code === '23505'
    && databaseError.table === 'users'
    && databaseError.constraint === 'users_email_key';
}

app.post('/v1/organizations', authRateLimit, async (req, res, next) => {
  try {
    const input = registrationSchema.parse(req.body);
    const salt = randomBytes(16);
    const passwordHash = (await scrypt(input.password, salt, 64)) as Buffer;
    let client: PoolClient | undefined;
    try {
      client = await pool.connect();
      await client.query('BEGIN');
      await client.query(`SELECT set_config('app.registration', 'true', true)`);
      const organizationId = randomUUID();
      await client.query(
        `INSERT INTO organizations (id, name, status) VALUES ($1, $2, 'pending')`,
        [organizationId, input.organizationName],
      );
      await client.query(`SELECT set_config('app.organization_id', $1, true)`, [organizationId]);
      const user = await client.query(
        `INSERT INTO users (organization_id, full_name, email, password_hash, password_salt, role)
         VALUES ($1, $2, $3, $4, $5, 'org_owner') RETURNING id`,
        [organizationId, input.fullName, input.email, passwordHash, salt],
      );
      await audit(client, organizationId, user.rows[0].id, 'organization.registered');
      await client.query('COMMIT');
      res.status(201).json({ organizationId, status: 'pending_approval' });
    } catch (error) {
      if (client) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          console.error(JSON.stringify({
            event: 'ORGANIZATION_REGISTRATION_ROLLBACK_FAILED',
            ...postgresErrorFields(rollbackError),
          }));
          client.release(rollbackError instanceof Error ? rollbackError : true);
          client = undefined;
          throw error;
        }
      }
      if (isDuplicateUserEmail(error)) return res.status(409).json({ error: 'email_already_registered' });
      throw error;
    } finally {
      client?.release();
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
  res.clearCookie('bk_session', {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: env.NODE_ENV === 'production' ? 'none' : 'strict',
    path: '/',
  });
  res.status(204).end();
});
app.get('/v1/me', requireSession, async (req, res, next) => {
  try {
    const { principal } = req;
    if (!principal) return res.status(401).json({ error: 'authentication_required' });
    if (!principal.organizationId) return res.json({ id: principal.userId, role: principal.role });
    const result = await withTenant(principal.organizationId, (client) => client.query(
      `SELECT o.id, o.name, o.status, o.api_enabled, u.email, u.role
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
      `SELECT id, name, environment, api_enabled, created_at FROM applications
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
         RETURNING id, name, environment, api_enabled, created_at`,
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
      `SELECT o.id, o.name, o.status, o.api_enabled, o.created_at, count(DISTINCT u.id)::int AS member_count,
              count(DISTINCT a.id)::int AS application_count
       FROM organizations o
       LEFT JOIN users u ON u.organization_id = o.id
       LEFT JOIN applications a ON a.organization_id = o.id
       GROUP BY o.id ORDER BY o.created_at DESC`,
    ));
    res.json({ organizations: result.rows });
  } catch (error) { next(error); }
});

app.get('/v1/admin/roles', requireSession, requirePlatformAdmin, (_req, res) => {
  res.json({
    roles: [
      { id: 'org_owner', label: 'Propietario de organización', scope: 'Administra su organización, miembros y aplicaciones.' },
      { id: 'org_admin', label: 'Administrador de organización', scope: 'Administra las aplicaciones y claves de su organización.' },
      { id: 'org_member', label: 'Miembro de organización', scope: 'Acceso de miembro a su organización.' },
      { id: 'platform_admin', label: 'Administrador de plataforma', scope: 'Acceso global a organizaciones, usuarios y permisos.' },
    ],
  });
});

app.get('/v1/admin/users', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const query = z.object({
      page: z.coerce.number().int().min(1).default(1),
      pageSize: z.coerce.number().int().min(1).max(100).default(25),
      search: z.string().trim().max(120).optional(),
      organizationId: z.string().uuid().optional(),
      role: z.enum(roles).optional(),
      active: z.enum(['true', 'false']).transform((value) => value === 'true').optional(),
    }).parse(req.query);
    const offset = (query.page - 1) * query.pageSize;
    const result = await withPlatform(async (client) => {
      const filters = [query.organizationId ?? null, query.role ?? null, query.active ?? null, query.search || null];
      const where = `($1::uuid IS NULL OR u.organization_id = $1)
        AND ($2::member_role IS NULL OR u.role = $2)
        AND ($3::boolean IS NULL OR u.active = $3)
        AND ($4::text IS NULL OR u.email ILIKE '%' || $4 || '%'
          OR u.id::text ILIKE '%' || $4 || '%'
          OR COALESCE(u.full_name, '') ILIKE '%' || $4 || '%'
          OR COALESCE(o.name, '') ILIKE '%' || $4 || '%')`;
      const [users, total] = await Promise.all([
        client.query(
          `SELECT u.id, u.full_name, u.email, u.organization_id, o.name AS organization_name,
                  u.role, u.active, u.created_at
           FROM users u LEFT JOIN organizations o ON o.id = u.organization_id
           WHERE ${where}
           ORDER BY u.created_at DESC, u.id
           LIMIT $5 OFFSET $6`,
          [...filters, query.pageSize, offset],
        ),
        client.query(
          `SELECT count(*)::int AS total
           FROM users u LEFT JOIN organizations o ON o.id = u.organization_id
           WHERE ${where}`,
          filters,
        ),
      ]);
      return { users: users.rows, total: total.rows[0].total };
    });
    res.json({ ...result, page: query.page, pageSize: query.pageSize });
  } catch (error) { next(error); }
});

app.get('/v1/admin/users/:id', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const userId = z.string().uuid().parse(req.params.id);
    const result = await withPlatform((client) => client.query(
      `SELECT u.id, u.full_name, u.email, u.organization_id, o.name AS organization_name,
              u.role, u.active, u.created_at
       FROM users u LEFT JOIN organizations o ON o.id = u.organization_id
       WHERE u.id = $1`,
      [userId],
    ));
    if (!result.rowCount) return res.status(404).json({ error: 'user_not_found' });
    res.json(result.rows[0]);
  } catch (error) { next(error); }
});

app.patch('/v1/admin/users/:id/role', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const userId = z.string().uuid().parse(req.params.id);
    const input = z.object({
      role: z.enum(roles),
      organizationId: z.string().uuid().nullable().optional(),
    }).parse(req.body);
    const actorId = req.principal!.userId;
    const result = await withPlatform(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(1180785123)');
      const target = await client.query(
        `SELECT id, email, organization_id, role, active FROM users WHERE id = $1 FOR UPDATE`,
        [userId],
      );
      if (!target.rowCount) return { status: 404 as const, error: 'user_not_found' as const };
      const previous = target.rows[0];
      if (previous.id === actorId) {
        await auditAdminUserChange(client, {
          actorId, targetId: userId, organizationId: previous.organization_id,
          action: 'role_changed', previousRole: previous.role, newRole: input.role,
          previousActive: previous.active, newActive: previous.active, outcome: 'rejected',
        });
        return { status: 403 as const, error: 'self_role_change_not_allowed' as const };
      }

      let organizationId: string | null = null;
      if (input.role === 'platform_admin') {
        if (input.organizationId) {
          await auditAdminUserChange(client, {
            actorId, targetId: userId, organizationId: previous.organization_id,
            action: 'role_changed', previousRole: previous.role, newRole: input.role,
            previousActive: previous.active, newActive: previous.active, outcome: 'rejected',
          });
          return { status: 400 as const, error: 'platform_admin_must_not_have_organization' as const };
        }
      } else {
        if (!input.organizationId) {
          await auditAdminUserChange(client, {
            actorId, targetId: userId, organizationId: previous.organization_id,
            action: 'role_changed', previousRole: previous.role, newRole: input.role,
            previousActive: previous.active, newActive: previous.active, outcome: 'rejected',
          });
          return { status: 400 as const, error: 'organization_required_for_role' as const };
        }
        const organization = await client.query(
          `SELECT id FROM organizations WHERE id = $1`,
          [input.organizationId],
        );
        if (!organization.rowCount) {
          await auditAdminUserChange(client, {
            actorId, targetId: userId, organizationId: previous.organization_id,
            action: 'role_changed', previousRole: previous.role, newRole: input.role,
            previousActive: previous.active, newActive: previous.active, outcome: 'rejected',
          });
          return { status: 400 as const, error: 'organization_not_found' as const };
        }
        organizationId = input.organizationId;
      }

      if (previous.active && previous.role === 'platform_admin' && input.role !== 'platform_admin') {
        const activeAdmins = await client.query(
          `SELECT count(*)::int AS total FROM users WHERE role = 'platform_admin' AND active = true`,
        );
        if (activeAdmins.rows[0].total <= 1) {
          await auditAdminUserChange(client, {
            actorId, targetId: userId, organizationId: previous.organization_id,
            action: 'role_changed', previousRole: previous.role, newRole: input.role,
            previousActive: previous.active, newActive: previous.active, outcome: 'rejected',
          });
          return { status: 409 as const, error: 'last_platform_admin_required' as const };
        }
      }

      const updated = await client.query(
        `UPDATE users SET role = $1, organization_id = $2 WHERE id = $3
         RETURNING id, full_name, email, organization_id, role, active, created_at`,
        [input.role, organizationId, userId],
      );
      const auditOrganizationId = previous.organization_id ?? organizationId;
      await auditAdminUserChange(client, {
        actorId, targetId: userId, organizationId: auditOrganizationId,
        action: 'role_changed', previousRole: previous.role, newRole: input.role,
        previousActive: previous.active, newActive: previous.active, outcome: 'success',
      });
      return { status: 200 as const, user: updated.rows[0] };
    });
    if (result.status !== 200) return res.status(result.status).json({ error: result.error });
    res.json(result.user);
  } catch (error) { next(error); }
});

app.patch('/v1/admin/users/:id/status', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const userId = z.string().uuid().parse(req.params.id);
    const { active } = z.object({ active: z.boolean() }).parse(req.body);
    const actorId = req.principal!.userId;
    const result = await withPlatform(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(1180785123)');
      const target = await client.query(
        `SELECT id, email, organization_id, role, active FROM users WHERE id = $1 FOR UPDATE`,
        [userId],
      );
      if (!target.rowCount) return { status: 404 as const, error: 'user_not_found' as const };
      const previous = target.rows[0];
      if (previous.id === actorId) {
        await auditAdminUserChange(client, {
          actorId, targetId: userId, organizationId: previous.organization_id,
          action: 'account_status_changed', previousRole: previous.role, newRole: previous.role,
          previousActive: previous.active, newActive: active, outcome: 'rejected',
        });
        return { status: 403 as const, error: 'self_status_change_not_allowed' as const };
      }
      if (previous.active && !active && previous.role === 'platform_admin') {
        const activeAdmins = await client.query(
          `SELECT count(*)::int AS total FROM users WHERE role = 'platform_admin' AND active = true`,
        );
        if (activeAdmins.rows[0].total <= 1) {
          await auditAdminUserChange(client, {
            actorId, targetId: userId, organizationId: previous.organization_id,
            action: 'account_status_changed', previousRole: previous.role, newRole: previous.role,
            previousActive: previous.active, newActive: active, outcome: 'rejected',
          });
          return { status: 409 as const, error: 'last_platform_admin_required' as const };
        }
      }
      const updated = await client.query(
        `UPDATE users SET active = $1 WHERE id = $2
         RETURNING id, full_name, email, organization_id, role, active, created_at`,
        [active, userId],
      );
      await auditAdminUserChange(client, {
        actorId, targetId: userId, organizationId: previous.organization_id,
        action: 'account_status_changed', previousRole: previous.role, newRole: previous.role,
        previousActive: previous.active, newActive: active, outcome: 'success',
      });
      return { status: 200 as const, user: updated.rows[0] };
    });
    if (result.status !== 200) return res.status(result.status).json({ error: result.error });
    res.json(result.user);
  } catch (error) { next(error); }
});

app.get('/v1/admin/audit-logs', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const query = z.object({
      page: z.coerce.number().int().min(1).default(1),
      pageSize: z.coerce.number().int().min(1).max(100).default(25),
    }).parse(req.query);
    const offset = (query.page - 1) * query.pageSize;
    const result = await withPlatform(async (client) => {
      const [logs, total] = await Promise.all([
        client.query(
          `SELECT l.id, l.actor_user_id, actor.email AS actor_email,
                  l.target_user_id, target.email AS target_email,
                  l.organization_id, o.name AS organization_name,
                  l.action, l.previous_role, l.new_role, l.previous_active, l.new_active,
                  l.outcome, l.created_at
           FROM admin_user_audit l
           LEFT JOIN users actor ON actor.id = l.actor_user_id
           LEFT JOIN users target ON target.id = l.target_user_id
           LEFT JOIN organizations o ON o.id = l.organization_id
           ORDER BY l.created_at DESC, l.id DESC LIMIT $1 OFFSET $2`,
          [query.pageSize, offset],
        ),
        client.query(`SELECT count(*)::int AS total FROM admin_user_audit`),
      ]);
      return { logs: logs.rows, total: total.rows[0].total };
    });
    res.json({ ...result, page: query.page, pageSize: query.pageSize });
  } catch (error) { next(error); }
});

app.get('/v1/admin/organizations/:id/applications', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const organizationId = z.string().uuid().parse(req.params.id);
    const result = await withPlatform(async (client) => {
      const applications = await client.query(
        `SELECT id, name, environment, api_enabled, created_at
         FROM applications WHERE organization_id = $1 ORDER BY created_at DESC`,
        [organizationId],
      );
      const keys = await client.query(
        `SELECT id, application_id, public_id, created_at, expires_at, revoked_at, last_used_at
         FROM api_keys WHERE organization_id = $1 ORDER BY created_at DESC`,
        [organizationId],
      );
      return applications.rows.map((application) => ({
        ...application,
        keys: keys.rows.filter((key) => key.application_id === application.id),
      }));
    });
    res.json({ applications: result });
  } catch (error) { next(error); }
});

app.post('/v1/admin/organizations/:id/api-access', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const organizationId = z.string().uuid().parse(req.params.id);
    const { enabled } = z.object({ enabled: z.boolean() }).parse(req.body);
    const principal = req.principal!;
    const organization = await withPlatform(async (client) => {
      const updated = await client.query(
        `UPDATE organizations SET api_enabled = $1, updated_at = now()
         WHERE id = $2 RETURNING id, api_enabled`,
        [enabled, organizationId],
      );
      if (!updated.rowCount) throw Object.assign(new Error('organization_not_found'), { status: 404 });
      await audit(client, organizationId, principal.userId, `organization.api_access_${enabled ? 'enabled' : 'disabled'}`, { enabled });
      return updated.rows[0];
    });
    res.json(organization);
  } catch (error) { next(error); }
});

app.post('/v1/admin/applications/:id/api-access', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const applicationId = z.string().uuid().parse(req.params.id);
    const { enabled } = z.object({ enabled: z.boolean() }).parse(req.body);
    const principal = req.principal!;
    const application = await withPlatform(async (client) => {
      const updated = await client.query(
        `UPDATE applications SET api_enabled = $1
         WHERE id = $2 RETURNING id, organization_id, api_enabled`,
        [enabled, applicationId],
      );
      if (!updated.rowCount) throw Object.assign(new Error('application_not_found'), { status: 404 });
      await audit(client, updated.rows[0].organization_id, principal.userId, `application.api_access_${enabled ? 'enabled' : 'disabled'}`, { applicationId, enabled });
      return updated.rows[0];
    });
    res.json(application);
  } catch (error) { next(error); }
});

app.delete('/v1/admin/organizations/:organizationId/applications/:applicationId/keys/:keyId', requireSession, requirePlatformAdmin, async (req, res, next) => {
  try {
    const organizationId = z.string().uuid().parse(req.params.organizationId);
    const principal = req.principal!;
    await withPlatform(async (client) => {
      const revoked = await client.query(
        `UPDATE api_keys SET revoked_at = now()
         WHERE id = $1 AND application_id = $2 AND organization_id = $3 AND revoked_at IS NULL
         RETURNING id`,
        [req.params.keyId, req.params.applicationId, organizationId],
      );
      if (!revoked.rowCount) throw Object.assign(new Error('key_not_found'), { status: 404 });
      await audit(client, organizationId, principal.userId, 'api_key.revoked_by_platform_admin', { keyId: revoked.rows[0].id });
    });
    res.status(204).end();
  } catch (error) { next(error); }
});

app.get('/v1/admin/usage/summary', requireSession, requirePlatformAdmin, async (_req, res, next) => {
  try {
    const result = await withPlatform(async (client) => {
      const summary = await client.query(
        `SELECT
           count(*) FILTER (WHERE created_at >= date_trunc('day', now()))::int AS today,
           count(*) FILTER (WHERE created_at >= now() - interval '7 days')::int AS last_7_days,
           count(*) FILTER (WHERE created_at >= date_trunc('month', now()))::int AS this_month,
           count(*) FILTER (WHERE status_code >= 400)::int AS errors
         FROM api_request_logs`,
      );
      const requests = await client.query(
        `SELECT l.id, o.name AS organization_name, a.name AS application_name,
                l.origin_domain, l.endpoint, l.method, l.status_code, l.duration_ms, l.created_at
         FROM api_request_logs l
         JOIN organizations o ON o.id = l.organization_id
         JOIN applications a ON a.id = l.application_id
         ORDER BY l.created_at DESC
         LIMIT 50`,
      );
      return { ...summary.rows[0], requests: requests.rows };
    });
    res.json(result);
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
    const outcome = await pool.connect().then(async (client) => {
      try {
        await client.query('BEGIN');
        await client.query(`SELECT set_config('app.key_auth', 'true', true)`);
        const key = await client.query(
          `SELECT k.id, k.public_id, k.organization_id, k.application_id,
                  o.status AS organization_status, o.api_enabled AS organization_api_enabled
           FROM api_keys k JOIN organizations o ON o.id = k.organization_id
           WHERE k.secret_hash = $1 AND k.revoked_at IS NULL
             AND (k.expires_at IS NULL OR k.expires_at > now())`,
          [digest],
        );
        if (!key.rowCount) {
          await client.query('COMMIT');
          return { key: null, error: 'invalid_api_key' as const };
        }
        const requestKey = key.rows[0];
        await client.query(`SELECT set_config('app.organization_id', $1, true)`, [requestKey.organization_id]);
        const application = await client.query(
          `SELECT api_enabled FROM applications WHERE id = $1 AND organization_id = $2`,
          [requestKey.application_id, requestKey.organization_id],
        );
        if (!application.rowCount) throw new Error('api_key_application_not_found');
        await client.query(`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, [requestKey.id]);
        const error = requestKey.organization_status !== 'active'
          ? 'organization_not_active' as const
          : (!requestKey.organization_api_enabled || !application.rows[0].api_enabled
            ? 'api_access_disabled' as const
            : null);
        const statusCode = error ? 403 : 200;
        await client.query(
          `INSERT INTO api_request_logs
           (organization_id, application_id, endpoint, method, status_code, duration_ms, origin_domain)
           VALUES ($1, $2, '/v1/integrations/ping', 'POST', $3, $4, $5)`,
          [
            requestKey.organization_id,
            requestKey.application_id,
            statusCode,
            Date.now() - requestStartedAt,
            (() => {
              try { return req.get('origin') ? new URL(req.get('origin')!).hostname : null; }
              catch { return null; }
            })(),
          ],
        );
        await client.query('COMMIT');
        return { key: requestKey, error };
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    });
    if (!outcome.key) return res.status(401).json({ error: outcome.error });
    if (outcome.error) return res.status(403).json({ error: outcome.error });
    res.json({ authenticated: true, environment: 'sandbox', message: 'Identificación de aplicación válida. Sin acceso a operaciones bancarias.' });
  } catch (error) { next(error); }
});

const errorHandler: express.ErrorRequestHandler = (error, _req, res, _next) => {
  if (error instanceof z.ZodError) {
    const details = error.issues.map(({ code, path, message }) => ({ code, path, message }));
    return res.status(400).json({ error: 'validation_error', details });
  }
  const databaseError = error as { code?: string; table?: string; column?: string };
  if (databaseError.code === '42703' || (databaseError.code === '42P01' && databaseError.table === 'admin_user_audit')) {
    console.error(JSON.stringify({
      event: 'DATABASE_SCHEMA_OUTDATED',
      ...postgresErrorFields(error),
    }));
    return res.status(503).json({
      error: 'database_schema_outdated',
      requiredMigration: databaseError.table === 'admin_user_audit' || databaseError.column === 'full_name'
        ? '003_admin_user_management.sql'
        : '002_admin_api_access.sql',
    });
  }
  const status = Number((error as { status?: number }).status) || 500;
  if (status >= 500) {
    console.error(JSON.stringify({
      event: 'API_INTERNAL_ERROR',
      ...postgresErrorFields(error),
    }));
  }
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
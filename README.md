# BANCO KIKE API PLATFORM

Monorepo independiente para el portal de desarrolladores y una API pública de Sandbox. No modifica ni duplica el backend bancario.

## Estado actual

Esta primera entrega proporciona una base ejecutable, enfocada en **Sandbox**:

- Portal Angular para registro, inicio/cierre de sesión, aplicaciones Sandbox y generación de API keys.
- API Express con sesiones en cookie `HttpOnly`, hash de contraseñas mediante scrypt, validación Zod, rate limit, CORS limitado y Swagger UI.
- PostgreSQL/Neon con organizaciones, usuarios, aplicaciones, claves, permisos, dominios, webhooks, métricas y auditoría.
- Aislamiento por organización con PostgreSQL Row-Level Security (RLS).
- Administración inicial para consultar organizaciones y aprobar, rechazar o suspender registros.
- Render Blueprint para la API y configuración Firebase Hosting para el portal.

**No está habilitado para dinero real.** No se implementan autenticación de clientes bancarios, saldo, transferencias, depósitos, OAuth/PKCE, entrega/reintentos de webhooks, verificación de identidad, administración de dominios permitidos, ni widget de usuario final. La API de integración solo ofrece un `ping` de Sandbox. Esas capacidades requieren contratos de integración, autorización y controles del backend bancario central; no deben simularse con credenciales de aplicación.

## Requisitos

- Node.js 24+
- PostgreSQL administrado por Neon
- Firebase CLI para Hosting y cuenta Render para el backend

## Desarrollo local

1. Crear una base de datos en Neon y ejecutar, en orden, `api/migrations/001_initial.sql` y `api/migrations/002_admin_api_access.sql` desde una conexión administrativa. La segunda migración agrega permisos explícitos de API por organización y aplicación; a los registros existentes les conserva el acceso que ya tenían.
2. Copiar `api/.env.example` a `api/.env` y configurar `DATABASE_URL`, `SESSION_SECRET` (mínimo 32 caracteres), `PORTAL_ORIGIN`, `API_ORIGIN` y `NODE_ENV`. No subir `.env`.
3. Instalar las dependencias del backend y del portal:

   ```sh
   npm install
   npm --prefix portal install
   ```

4. Arrancar la API y el portal en terminales separadas:

   ```sh
   npm run api:dev
   ```

   ```sh
   npm --prefix portal start
   ```

5. Abrir el portal en `http://localhost:4200` y la documentación en `http://localhost:3000/docs`.

El primer registro queda en estado pendiente. Para habilitar la administración de la plataforma, un operador debe verificar la identidad del administrador y asignar `platform_admin` desde un procedimiento administrativo seguro en Neon. No se asigna ese rol durante el registro público. Con la migración RLS aplicada, el operador puede usar una sesión controlada como esta:

```sql
BEGIN;
SET LOCAL app.platform_admin = 'true';
UPDATE users
SET organization_id = NULL, role = 'platform_admin'
WHERE email = 'admin-verificado@bancokike.com';
COMMIT;
```

El cambio de rol solo debe ejecutarse tras comprobar la identidad por un canal independiente y con un usuario de base de datos autorizado.

## Despliegue

- **API:** configurar el servicio web Render desde `render.yaml`; cargar `DATABASE_URL` y aplicar las migraciones, especialmente `002_admin_api_access.sql`, antes de publicar una versión que dependa de `api_enabled`. `/health/ready` comprueba ahora que las columnas requeridas existen, por lo que Render no enviará tráfico a una instancia con un esquema incompatible. Render ofrece una URL `*.onrender.com` sin configurar un dominio propio.
- **Portal:** ejecutar `npm --prefix portal run build` y desplegar `portal/dist/portal/browser` en Firebase Hosting. Firebase proporciona automáticamente una URL `*.web.app`; no hace falta asociar un dominio propio.

## Seguridad / operación

- Las API keys se generan con aleatoriedad criptográfica, se almacena solo SHA-256 del valor completo y se entregan una sola vez. No ponerlas en JavaScript público, URL, repositorios ni logs.
- Una API key identifica la aplicación; no autentica a personas. Las operaciones bancarias deben usar el flujo de identidad del banco.
- El acceso de Sandbox requiere que la organización esté activa y que el administrador haya habilitado el acceso API tanto para la organización como para la aplicación. Las claves creadas antes de aplicar la migración conservan el acceso de su organización activa y aplicación existente.
- Las API keys son credenciales de servidor. No invocar `POST /v1/integrations/ping` desde JavaScript de terceros ni incluir una clave en el widget.
- Las cookies de sesión son `HttpOnly`, `SameSite=None` y `Secure` en producción para permitir solicitudes entre Firebase Hosting y Render; en desarrollo usan `SameSite=Strict`. Se limitan a ocho horas. Los cambios requieren JSON y validación del origen.
- El backend no registra contraseñas, tokens, API keys ni NIP. Los registros de uso no incluyen IP; el campo de origen se limita a la solicitud de prueba.
- Aplicar la migración con el rol de Neon apropiado. El runtime debe usar un rol no superusuario y no propietario de las tablas; de lo contrario, PostgreSQL puede omitir RLS. El usuario de aplicación necesita `SELECT/INSERT/UPDATE` explícitos según las operaciones utilizadas.
- La cuenta inicial de plataforma debe ser creada y verificada por el operador. Los administradores deben usar MFA/SSO antes de producción.

## Endpoints disponibles

- `POST /v1/organizations` — solicitar registro (pendiente).
- `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/me` — sesión del portal.
- `GET /v1/applications`, `POST /v1/applications` — aplicaciones de la organización.
- `GET /v1/applications/{id}/keys`, `POST /v1/applications/{id}/keys`, `DELETE /v1/applications/{applicationId}/keys/{keyId}` — administrar claves.
- `POST /v1/integrations/ping` — validar identificación de aplicación en Sandbox.
- `GET /v1/admin/organizations`, `POST /v1/admin/organizations/{id}/decision` — consulta y aprobación/suspensión de organizaciones.
- `POST /v1/admin/organizations/{id}/api-access`, `GET /v1/admin/organizations/{id}/applications`, `POST /v1/admin/applications/{id}/api-access`, `DELETE /v1/admin/organizations/{organizationId}/applications/{applicationId}/keys/{keyId}` — habilitar/deshabilitar acceso al API por organización o aplicación, consultar metadatos de claves y revocarlas desde el panel de administración. Nunca se muestran secretos de claves.
- `GET /v1/admin/usage/summary` — resumen global y últimas 50 solicitudes a `/v1/integrations/ping` autenticadas con una clave vigente, incluyendo resultados bloqueados por estado de organización o permisos API. Las claves inválidas no se asocian a registros; el dominio de origen no incluye una ruta de página.
- `GET /docs`, `GET /openapi.json` — documentación interactiva y especificación.
- `GET /health/live`, `GET /health/ready` — comprobaciones operativas.

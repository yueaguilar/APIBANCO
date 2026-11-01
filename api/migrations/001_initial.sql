CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE organization_status AS ENUM ('pending', 'active', 'rejected', 'suspended');
CREATE TYPE application_environment AS ENUM ('sandbox', 'production');
CREATE TYPE member_role AS ENUM ('org_owner', 'org_admin', 'org_member', 'platform_admin');

CREATE TABLE organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
  status organization_status NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  email text NOT NULL UNIQUE,
  password_hash bytea NOT NULL,
  password_salt bytea NOT NULL,
  role member_role NOT NULL DEFAULT 'org_member',
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((role = 'platform_admin' AND organization_id IS NULL) OR (role <> 'platform_admin' AND organization_id IS NOT NULL))
);

CREATE TABLE applications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
  environment application_environment NOT NULL DEFAULT 'sandbox',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, organization_id)
);

CREATE TABLE api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  application_id uuid NOT NULL,
  public_id text NOT NULL UNIQUE,
  secret_hash bytea NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  FOREIGN KEY (application_id, organization_id) REFERENCES applications(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE application_permissions (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  application_id uuid NOT NULL,
  permission text NOT NULL CHECK (permission ~ '^[a-z][a-z0-9_.:-]{1,63}$'),
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (application_id, permission),
  FOREIGN KEY (application_id, organization_id) REFERENCES applications(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE authorized_domains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  application_id uuid NOT NULL,
  domain text NOT NULL CHECK (length(domain) <= 253),
  verified_at timestamptz,
  FOREIGN KEY (application_id, organization_id) REFERENCES applications(id, organization_id) ON DELETE CASCADE,
  UNIQUE (application_id, domain)
);

CREATE TABLE webhook_endpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  application_id uuid NOT NULL,
  url text NOT NULL CHECK (url LIKE 'https://%'),
  event_types text[] NOT NULL DEFAULT '{}',
  signing_secret_hash bytea NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (application_id, organization_id) REFERENCES applications(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE api_request_logs (
  id bigserial PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  application_id uuid NOT NULL,
  endpoint text NOT NULL,
  method text NOT NULL,
  status_code integer NOT NULL,
  duration_ms integer NOT NULL CHECK (duration_ms >= 0),
  origin_domain text,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (application_id, organization_id) REFERENCES applications(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE audit_events (
  id bigserial PRIMARY KEY,
  organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX api_keys_org_active_idx ON api_keys (organization_id, application_id) WHERE revoked_at IS NULL;
CREATE INDEX request_logs_org_created_idx ON api_request_logs (organization_id, created_at DESC);
CREATE INDEX audit_events_org_created_idx ON audit_events (organization_id, created_at DESC);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organizations_tenant_select ON organizations FOR SELECT
  USING (
    id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.auth_lookup', true) = 'true'
    OR current_setting('app.key_auth', true) = 'true'
    OR current_setting('app.platform_admin', true) = 'true'
  );
CREATE POLICY organizations_controlled_insert ON organizations FOR INSERT
  WITH CHECK (
    current_setting('app.registration', true) = 'true'
    OR current_setting('app.platform_admin', true) = 'true'
  );
CREATE POLICY organizations_platform_update ON organizations FOR UPDATE
  USING (current_setting('app.platform_admin', true) = 'true')
  WITH CHECK (current_setting('app.platform_admin', true) = 'true');
CREATE POLICY organizations_platform_delete ON organizations FOR DELETE
  USING (current_setting('app.platform_admin', true) = 'true');

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_select ON users FOR SELECT
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.auth_lookup', true) = 'true'
    OR current_setting('app.platform_admin', true) = 'true'
  );
CREATE POLICY users_tenant_insert ON users FOR INSERT
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );
CREATE POLICY users_tenant_update ON users FOR UPDATE
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  )
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );
CREATE POLICY users_tenant_delete ON users FOR DELETE
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );

ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE applications FORCE ROW LEVEL SECURITY;
CREATE POLICY applications_tenant_isolation ON applications
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  )
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );

ALTER TABLE application_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY application_permissions_tenant_isolation ON application_permissions
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  )
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY api_keys_tenant_isolation ON api_keys
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.key_auth', true) = 'true'
    OR current_setting('app.platform_admin', true) = 'true'
  )
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.key_auth', true) = 'true'
    OR current_setting('app.platform_admin', true) = 'true'
  );

ALTER TABLE authorized_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorized_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY authorized_domains_tenant_isolation ON authorized_domains
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  )
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );

ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoints_tenant_isolation ON webhook_endpoints
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  )
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );

ALTER TABLE api_request_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_request_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY request_logs_tenant_isolation ON api_request_logs
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  )
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_tenant_isolation ON audit_events
  USING (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  )
  WITH CHECK (
    organization_id = nullif(current_setting('app.organization_id', true), '')::uuid
    OR current_setting('app.platform_admin', true) = 'true'
  );

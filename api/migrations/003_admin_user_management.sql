ALTER TABLE users
  ADD COLUMN IF NOT EXISTS full_name text;

CREATE TABLE IF NOT EXISTS admin_user_audit (
  id bigserial PRIMARY KEY,
  actor_user_id uuid NOT NULL,
  target_user_id uuid NOT NULL,
  organization_id uuid,
  action text NOT NULL CHECK (action IN ('role_changed', 'account_status_changed')),
  previous_role member_role NOT NULL,
  new_role member_role NOT NULL,
  previous_active boolean NOT NULL,
  new_active boolean NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('success', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_user_audit_created_idx ON admin_user_audit (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS admin_user_audit_target_idx ON admin_user_audit (target_user_id, created_at DESC);

ALTER TABLE admin_user_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_user_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_user_audit_platform_select ON admin_user_audit;
CREATE POLICY admin_user_audit_platform_select ON admin_user_audit
  FOR SELECT USING (current_setting('app.platform_admin', true) = 'true');
DROP POLICY IF EXISTS admin_user_audit_platform_insert ON admin_user_audit;
CREATE POLICY admin_user_audit_platform_insert ON admin_user_audit
  FOR INSERT WITH CHECK (current_setting('app.platform_admin', true) = 'true');

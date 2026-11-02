ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS api_enabled boolean NOT NULL DEFAULT false;

UPDATE organizations
SET api_enabled = (status = 'active');

ALTER TABLE applications
  ADD COLUMN IF NOT EXISTS api_enabled boolean NOT NULL DEFAULT false;

UPDATE applications
SET api_enabled = true;

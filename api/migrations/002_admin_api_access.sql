DO $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'organizations'
      AND column_name = 'api_enabled'
  ) THEN
    ALTER TABLE organizations
      ADD COLUMN api_enabled boolean NOT NULL DEFAULT false;
    UPDATE organizations SET api_enabled = (status = 'active');
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'applications'
      AND column_name = 'api_enabled'
  ) THEN
    ALTER TABLE applications
      ADD COLUMN api_enabled boolean NOT NULL DEFAULT false;
    UPDATE applications SET api_enabled = true;
  END IF;
END;
$migration$;

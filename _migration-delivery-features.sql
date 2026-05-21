-- =============================================================================
-- Factory Portal — delivery features schema
-- =============================================================================
-- Adds:
--   1. New columns on `deliveries` for sign-off + driver assignment
--   2. `delivery_log` table for the activity log (status changes + manual notes)
--   3. `delivery_photos` table for the photo evidence
--
-- To deploy:
--   1. Supabase Dashboard → SQL Editor → New query → paste this file → Run
--   2. Supabase Dashboard → Storage → New bucket → name: "delivery-photos"
--      → public bucket: YES → Save
-- =============================================================================

-- ------------------------------------------------------------------
-- 1. New columns on existing `deliveries` table
-- ------------------------------------------------------------------
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS signed_off_at TIMESTAMPTZ;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS signed_off_by_name TEXT;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS signature_url TEXT;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS assigned_driver_id INTEGER REFERENCES team_members(id) ON DELETE SET NULL;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS assigned_driver_name TEXT;

-- ------------------------------------------------------------------
-- 2. delivery_log: activity trail (status changes + manual notes)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS delivery_log (
  id BIGSERIAL PRIMARY KEY,
  delivery_id BIGINT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,

  -- What kind of event:
  --   'created'         — delivery row created
  --   'status_changed'  — status field changed
  --   'note'            — manual note added by a team member
  --   'photo_added'     — driver attached a photo
  --   'signed_off'      — customer signature captured
  --   'driver_assigned' — assigned to a driver
  action TEXT NOT NULL,

  -- Human-readable detail (e.g. "Scheduled → Delivered", or the note text)
  detail TEXT,

  -- Structured payload (e.g. {"from":"Scheduled","to":"Delivered"} or {"photo_id":12})
  metadata JSONB DEFAULT '{}'::jsonb,

  -- Who did it
  user_id INTEGER REFERENCES team_members(id) ON DELETE SET NULL,
  user_name TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_delivery_log_delivery_id ON delivery_log (delivery_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_delivery_log_created_at ON delivery_log (created_at DESC);

-- ------------------------------------------------------------------
-- 3. delivery_photos: photo evidence linked to each delivery
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS delivery_photos (
  id BIGSERIAL PRIMARY KEY,
  delivery_id BIGINT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  photo_url TEXT NOT NULL,             -- public URL of the file in the `delivery-photos` bucket
  caption TEXT,                        -- optional caption (e.g. "Front door", "Behind shed")
  taken_by_id INTEGER REFERENCES team_members(id) ON DELETE SET NULL,
  taken_by_name TEXT,
  taken_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_delivery_photos_delivery_id ON delivery_photos (delivery_id, taken_at DESC);

-- ------------------------------------------------------------------
-- 4. Auto-update updated_at on deliveries (if you ever want to use it)
-- ------------------------------------------------------------------
-- Skipped — your existing deliveries table doesn't track updated_at and we
-- don't strictly need it; the delivery_log gives us the timeline.

-- ------------------------------------------------------------------
-- 5. Permissions (matches your existing pattern — anon key full access)
-- ------------------------------------------------------------------
ALTER TABLE delivery_log    DISABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_photos DISABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON delivery_log    TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON delivery_photos TO anon;
GRANT USAGE, SELECT ON SEQUENCE delivery_log_id_seq    TO anon;
GRANT USAGE, SELECT ON SEQUENCE delivery_photos_id_seq TO anon;

-- ------------------------------------------------------------------
-- 6. Auto-log new deliveries via a trigger (so we never miss the "created" event)
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION log_delivery_created()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO delivery_log (delivery_id, action, detail, metadata, created_at)
  VALUES (NEW.id, 'created', 'Delivery scheduled for ' || NEW.scheduled_date,
          jsonb_build_object('status', NEW.status, 'job_number', NEW.job_number, 'customer', NEW.customer),
          NEW.created_at);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS deliveries_log_created ON deliveries;
CREATE TRIGGER deliveries_log_created
AFTER INSERT ON deliveries
FOR EACH ROW EXECUTE FUNCTION log_delivery_created();

-- ------------------------------------------------------------------
-- 7. Auto-log status changes on deliveries
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION log_delivery_status_change()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status IS DISTINCT FROM NEW.status THEN
    INSERT INTO delivery_log (delivery_id, action, detail, metadata)
    VALUES (NEW.id, 'status_changed',
            COALESCE(OLD.status, '(none)') || ' → ' || COALESCE(NEW.status, '(none)'),
            jsonb_build_object('from', OLD.status, 'to', NEW.status));
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS deliveries_log_status ON deliveries;
CREATE TRIGGER deliveries_log_status
AFTER UPDATE ON deliveries
FOR EACH ROW EXECUTE FUNCTION log_delivery_status_change();

-- =============================================================================
-- Verification queries (run separately):
-- =============================================================================
-- SELECT column_name, data_type FROM information_schema.columns
-- WHERE table_name = 'deliveries' AND column_name IN
--   ('signed_off_at','signed_off_by_name','signature_url','assigned_driver_id','assigned_driver_name');
--
-- SELECT * FROM delivery_log ORDER BY created_at DESC LIMIT 5;
-- SELECT * FROM delivery_photos ORDER BY taken_at DESC LIMIT 5;
--
-- -- Force a test row to fire the trigger:
-- UPDATE deliveries SET status = status WHERE id = (SELECT id FROM deliveries LIMIT 1);
-- SELECT * FROM delivery_log WHERE delivery_id = (SELECT id FROM deliveries LIMIT 1) ORDER BY created_at DESC;
-- =============================================================================

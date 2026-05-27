-- =============================================================================
-- Factory Portal — add work_type to deliveries (DEL / SCR / SW)
-- =============================================================================
-- Lets the Deliveries calendar track three kinds of scheduled work:
--   DEL  = Delivery
--   SCR  = Screens (screen install)
--   SW   = Site work
--
-- Existing rows are backfilled to 'DEL' so nothing changes for current data.
-- Run in Supabase Dashboard → SQL Editor → New Query.
-- =============================================================================

ALTER TABLE deliveries
  ADD COLUMN IF NOT EXISTS work_type TEXT DEFAULT 'DEL';

-- Backfill any nulls just in case
UPDATE deliveries SET work_type = 'DEL' WHERE work_type IS NULL;

-- Optional: constrain values (recommended but not required)
ALTER TABLE deliveries
  DROP CONSTRAINT IF EXISTS deliveries_work_type_check;
ALTER TABLE deliveries
  ADD CONSTRAINT deliveries_work_type_check
  CHECK (work_type IN ('DEL','SCR','SW'));

-- Verify
SELECT work_type, COUNT(*) AS n
FROM deliveries
GROUP BY work_type
ORDER BY work_type;

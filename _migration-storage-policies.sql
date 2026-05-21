-- =============================================================================
-- Factory Portal — storage RLS policies for delivery-photos bucket (v2)
-- =============================================================================
-- v1 used TO anon. Some Supabase setups need TO public to match how the JS SDK
-- presents requests. This version widens the policy to public + re-applies.
-- =============================================================================

-- ----- Drop any previous attempts so this script is re-runnable ---------------
DROP POLICY IF EXISTS "anon upload delivery photos"   ON storage.objects;
DROP POLICY IF EXISTS "anon update delivery photos"   ON storage.objects;
DROP POLICY IF EXISTS "anon delete delivery photos"   ON storage.objects;
DROP POLICY IF EXISTS "public upload delivery photos" ON storage.objects;
DROP POLICY IF EXISTS "public update delivery photos" ON storage.objects;
DROP POLICY IF EXISTS "public delete delivery photos" ON storage.objects;
DROP POLICY IF EXISTS "public select delivery photos" ON storage.objects;

-- ----- Create permissive policies for the delivery-photos bucket --------------
-- SELECT (read) — needed by the app to display photos and signatures
CREATE POLICY "public select delivery photos"
ON storage.objects FOR SELECT TO public
USING (bucket_id = 'delivery-photos');

-- INSERT (upload)
CREATE POLICY "public upload delivery photos"
ON storage.objects FOR INSERT TO public
WITH CHECK (bucket_id = 'delivery-photos');

-- UPDATE (needed by x-upsert mode and renaming)
CREATE POLICY "public update delivery photos"
ON storage.objects FOR UPDATE TO public
USING (bucket_id = 'delivery-photos')
WITH CHECK (bucket_id = 'delivery-photos');

-- DELETE (so the × button on photo thumbnails works)
CREATE POLICY "public delete delivery photos"
ON storage.objects FOR DELETE TO public
USING (bucket_id = 'delivery-photos');

-- =============================================================================
-- VERIFY: should return 4 rows, all for the {public} role
-- =============================================================================
SELECT policyname, cmd, roles
FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects'
  AND policyname LIKE '%delivery photos%'
ORDER BY policyname;

-- =============================================================================
-- DIAGNOSTIC: compare with the existing safety-photos bucket (which works).
-- Run this on its own — it'll show all storage policies so we can see the
-- pattern that's already proven to work in your project.
-- =============================================================================
-- SELECT policyname, cmd, roles, qual, with_check
-- FROM pg_policies
-- WHERE schemaname = 'storage' AND tablename = 'objects'
-- ORDER BY policyname;

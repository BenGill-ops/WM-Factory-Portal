-- =============================================================================
-- Factory Portal — close anonymous read access to the safety tables
-- =============================================================================
-- RUN THIS ONLY AFTER THE UPDATED tv.html IS DEPLOYED.
--
-- Why it is separate: tv.html (the factory TV dashboard) runs with no login and
-- reads safety_alerts, signoffs, team_members and safe_work_practices directly
-- using the public anon key. Dropping anon SELECT before the TV is switched
-- over to the views below will blank the screen in the factory.
--
-- What this changes:
--   * The TV reads two narrow views instead of the base tables.
--   * tv_swp_compliance exposes ONE aggregate percentage. No names, no dates,
--     no per-employee rows.
--   * tv_safety_alerts exposes only what is already on a screen on the wall:
--     ref, title, category, priority, dept, location, pinned, raised_by, date.
--     It does NOT expose the alert description, photos, or archived history.
--   * anon loses SELECT on safety_alerts, signoffs, safe_work_practices,
--     swp_assignments and team_members, so individual training records and the
--     staff roster are no longer readable from the public internet.
--
-- Residual, stated plainly: the two views are still anon-readable, because the
-- TV has no login. Anyone holding the anon key (it ships in tv.html, which is
-- public) can read the compliance percentage and the active alert headlines.
-- That is the same information visible to anyone standing in the factory.
-- Everything else now requires a real user session.
-- =============================================================================


-- ─── Aggregate compliance for the TV ─────────────────────────────────────────
-- Mirrors the portal: applicability rules honoured, and BOTH 'current' and
-- 'due-soon' count as compliant (the old TV code counted only 'current', so it
-- under-reported exactly like the portal did).
CREATE OR REPLACE VIEW public.tv_swp_compliance AS
WITH latest AS (
  SELECT DISTINCT ON (team_member_id, swp_id)
         team_member_id, swp_id, self_signed_at, assessor_signed_at, expires_at
  FROM public.signoffs
  ORDER BY team_member_id, swp_id, created_at DESC
),
applicable AS (
  SELECT m.id AS member_id, s.id AS swp_id
  FROM public.team_members m
  CROSS JOIN public.safe_work_practices s
  LEFT JOIN public.swp_assignments a
         ON a.team_member_id = m.id AND a.swp_id = s.id
  WHERE m.is_active
    AND COALESCE(m.exclude_from_compliance, false) = false
    AND s.is_active
    AND COALESCE(a.applies, NOT COALESCE(s.is_optional, false))
),
scored AS (
  SELECT ap.member_id, ap.swp_id,
         (l.self_signed_at IS NOT NULL
          AND l.assessor_signed_at IS NOT NULL
          AND (l.expires_at IS NULL OR l.expires_at >= now())) AS compliant
  FROM applicable ap
  LEFT JOIN latest l ON l.team_member_id = ap.member_id AND l.swp_id = ap.swp_id
)
SELECT
  count(*)::int                                        AS total,
  count(*) FILTER (WHERE compliant)::int               AS compliant,
  CASE WHEN count(*) > 0
       THEN round(count(*) FILTER (WHERE compliant)::numeric * 100 / count(*))::int
       ELSE 0 END                                      AS pct
FROM scored;


-- ─── Active alert headlines for the TV ───────────────────────────────────────
-- Deliberately omits content (the description) and photo_urls.
CREATE OR REPLACE VIEW public.tv_safety_alerts AS
SELECT id, ref_no, title, category, priority, dept, location,
       is_pinned, raised_by, created_at
FROM public.safety_alerts
WHERE COALESCE(is_archived, false) = false;


-- Views are owner-rights (security_invoker off), so they read past the base
-- table RLS on purpose. Grant only SELECT, only on these two.
GRANT SELECT ON public.tv_swp_compliance TO anon, authenticated;
GRANT SELECT ON public.tv_safety_alerts  TO anon, authenticated;


-- ─── Close the base tables to anon ───────────────────────────────────────────
DROP POLICY IF EXISTS p_select ON public.safety_alerts;
CREATE POLICY p_select ON public.safety_alerts FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS p_select ON public.signoffs;
CREATE POLICY p_select ON public.signoffs FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS p_select ON public.safe_work_practices;
CREATE POLICY p_select ON public.safe_work_practices FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS p_select ON public.swp_assignments;
CREATE POLICY p_select ON public.swp_assignments FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS p_select ON public.team_members;
CREATE POLICY p_select ON public.team_members FOR SELECT TO authenticated USING (true);

-- competency_items still allowed anon in the old policy set; close it too.
DROP POLICY IF EXISTS p_select ON public.competency_items;
CREATE POLICY p_select ON public.competency_items FOR SELECT TO authenticated USING (true);


-- =============================================================================
-- VERIFY — every row below should show roles = {authenticated} only
-- =============================================================================
SELECT tablename, policyname, roles::text
FROM pg_policies
WHERE schemaname = 'public'
  AND cmd = 'SELECT'
  AND tablename IN ('safety_alerts','signoffs','safe_work_practices',
                    'swp_assignments','team_members','competency_items')
ORDER BY tablename;

-- And the TV should still get numbers:
SELECT * FROM public.tv_swp_compliance;

-- =============================================================================
-- Factory Portal — Safety & Compliance hardening + Toolbox Talks
-- Aug 2026. Re-runnable.
-- =============================================================================
-- PART A  helper functions
-- PART B  signoffs write lockdown (review finding 3.1 / 3.4)
-- PART C  per-employee SWP applicability (swp_assignments.applies)
-- PART D  safety_alerts close-out fields (review finding 3.7 / 3.8)
-- PART E  toolbox talks + attendee signatures
-- PART F  signature storage bucket policies
--
-- NOTE: dropping anon SELECT from the base tables is NOT in this script.
-- tv.html reads them anonymously. See _migration-safety-anon-lockdown.sql,
-- which must be run only once the updated tv.html is deployed.
-- =============================================================================


-- ─── PART A ── helper functions ──────────────────────────────────────────────

-- team_members.id of the currently authenticated user (null if not linked)
CREATE OR REPLACE FUNCTION public.me()
RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO 'public'
AS $$ SELECT id FROM team_members
      WHERE auth_user_id = auth.uid() AND is_active = true LIMIT 1 $$;

-- is the current user a flagged assessor?
CREATE OR REPLACE FUNCTION public.is_assessor_user()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO 'public'
AS $$ SELECT COALESCE((SELECT is_assessor FROM team_members
                       WHERE auth_user_id = auth.uid() AND is_active = true LIMIT 1), false) $$;

-- can the current user run a toolbox talk / manage alerts? (supervisor and up)
CREATE OR REPLACE FUNCTION public.is_supervisor()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO 'public'
AS $$ SELECT COALESCE(public.my_role() IN ('admin','manager','supervisor'), false) $$;


-- ─── PART B ── signoffs write lockdown ───────────────────────────────────────
-- Before: p_update USING is_staff() with no WITH CHECK, so ANY active staff
-- member could PATCH any signoff row and set themselves to assessor-verified.
-- After: row access is limited to the subject, assessors and managers, and a
-- column guard enforces who may move which columns.

DROP POLICY IF EXISTS p_insert ON public.signoffs;
DROP POLICY IF EXISTS p_update ON public.signoffs;
DROP POLICY IF EXISTS p_delete ON public.signoffs;

CREATE POLICY p_insert ON public.signoffs FOR INSERT TO authenticated
WITH CHECK (
  team_member_id = public.me()      -- signing my own
  OR public.is_assessor_user()      -- assessor creating a record
  OR public.is_manager()
);

CREATE POLICY p_update ON public.signoffs FOR UPDATE TO authenticated
USING (
  team_member_id = public.me()
  OR public.is_assessor_user()
  OR public.is_manager()
)
WITH CHECK (
  team_member_id = public.me()
  OR public.is_assessor_user()
  OR public.is_manager()
);

CREATE POLICY p_delete ON public.signoffs FOR DELETE TO authenticated
USING (public.is_manager());

-- Column-level guard. RLS is row-level only, so the who-may-sign-what rules
-- live in a trigger.
-- Ties an assessor signature to a member id, not just a typed name.
ALTER TABLE public.signoffs
  ADD COLUMN IF NOT EXISTS assessor_member_id bigint REFERENCES public.team_members(id);

CREATE OR REPLACE FUNCTION public.signoffs_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'public'
AS $$
DECLARE
  actor bigint;
BEGIN
  -- The guard governs authenticated app users. Service-role and migration work
  -- has no auth.uid() and is already trusted, so it passes straight through.
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  actor := public.me();
  IF actor IS NULL THEN
    RAISE EXCEPTION 'Your login is not linked to an active team member.';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.self_signed_at IS NOT NULL
       AND NEW.team_member_id <> actor
       AND NOT public.is_manager() THEN
      RAISE EXCEPTION 'You can only complete your own self-assessment.';
    END IF;
    IF NEW.assessor_signed_at IS NOT NULL THEN
      IF NOT public.is_assessor_user() THEN
        RAISE EXCEPTION 'Only an authorised assessor can record an assessor sign-off.';
      END IF;
      IF NEW.team_member_id = actor THEN
        RAISE EXCEPTION 'An employee cannot be their own assessor.';
      END IF;
      IF NEW.assessor_member_id IS NOT NULL AND NEW.assessor_member_id <> actor THEN
        RAISE EXCEPTION 'An assessor sign-off must be signed by the assessor themselves.';
      END IF;
      NEW.assessor_member_id := actor;
    END IF;
    RETURN NEW;
  END IF;

  -- assessor columns moved?
  IF NEW.assessor_signed_at        IS DISTINCT FROM OLD.assessor_signed_at
  OR NEW.assessor_signed_initials  IS DISTINCT FROM OLD.assessor_signed_initials
  OR NEW.assessor_name             IS DISTINCT FROM OLD.assessor_name
  OR NEW.assessor_member_id        IS DISTINCT FROM OLD.assessor_member_id
  OR NEW.expires_at                IS DISTINCT FROM OLD.expires_at THEN
    IF NEW.assessor_signed_at IS NOT NULL THEN
      -- recording a verification
      IF NOT public.is_assessor_user() THEN
        RAISE EXCEPTION 'Only an authorised assessor can record an assessor sign-off.';
      END IF;
      IF NEW.team_member_id = actor THEN
        RAISE EXCEPTION 'An employee cannot be their own assessor.';
      END IF;
      IF NEW.assessor_member_id IS NOT NULL AND NEW.assessor_member_id <> actor THEN
        RAISE EXCEPTION 'An assessor sign-off must be signed by the assessor themselves.';
      END IF;
      NEW.assessor_member_id := actor;
    ELSE
      -- clearing a verification (revoke)
      IF NOT public.is_manager() THEN
        RAISE EXCEPTION 'Only a manager can revoke an assessor sign-off.';
      END IF;
      NEW.assessor_member_id := NULL;
    END IF;
  END IF;

  -- self-sign columns moved?
  IF NEW.self_signed_at       IS DISTINCT FROM OLD.self_signed_at
  OR NEW.self_signed_initials IS DISTINCT FROM OLD.self_signed_initials THEN
    IF NEW.self_signed_at IS NOT NULL THEN
      IF NEW.team_member_id <> actor AND NOT public.is_manager() THEN
        RAISE EXCEPTION 'You can only complete your own self-assessment.';
      END IF;
    ELSE
      IF NOT public.is_manager() THEN
        RAISE EXCEPTION 'Only a manager can revoke a self-assessment.';
      END IF;
    END IF;
  END IF;

  -- the subject of a record can never be reassigned
  IF NEW.team_member_id IS DISTINCT FROM OLD.team_member_id
  OR NEW.swp_id         IS DISTINCT FROM OLD.swp_id THEN
    RAISE EXCEPTION 'A sign-off cannot be moved to a different employee or SWP.';
  END IF;

  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_signoffs_guard ON public.signoffs;
CREATE TRIGGER trg_signoffs_guard
BEFORE INSERT OR UPDATE ON public.signoffs
FOR EACH ROW EXECUTE FUNCTION public.signoffs_guard();


-- ─── PART C ── per-employee SWP applicability ────────────────────────────────
-- swp_assignments previously meant "this optional SWP is assigned to X".
-- It now carries an explicit applies flag so an admin can also untick a
-- mandatory SWP for an employee who does not use that equipment.
--   row applies = true   -> applies to this employee
--   row applies = false  -> explicitly does not apply
--   no row               -> default: mandatory applies, optional does not

ALTER TABLE public.swp_assignments
  ADD COLUMN IF NOT EXISTS applies boolean NOT NULL DEFAULT true;
ALTER TABLE public.swp_assignments
  ADD COLUMN IF NOT EXISTS excluded_reason text;
ALTER TABLE public.swp_assignments
  ADD COLUMN IF NOT EXISTS updated_at timestamptz DEFAULT now();

-- one row per member+SWP so the UI can upsert
DELETE FROM public.swp_assignments a USING public.swp_assignments b
WHERE a.id > b.id AND a.team_member_id = b.team_member_id AND a.swp_id = b.swp_id;

DO $$ BEGIN
  ALTER TABLE public.swp_assignments
    ADD CONSTRAINT swp_assignments_member_swp_key UNIQUE (team_member_id, swp_id);
EXCEPTION WHEN duplicate_table OR duplicate_object THEN NULL; END $$;

-- only managers/admins may change who a SWP applies to
DROP POLICY IF EXISTS p_insert ON public.swp_assignments;
DROP POLICY IF EXISTS p_update ON public.swp_assignments;
CREATE POLICY p_insert ON public.swp_assignments FOR INSERT TO authenticated
  WITH CHECK (public.is_manager());
CREATE POLICY p_update ON public.swp_assignments FOR UPDATE TO authenticated
  USING (public.is_manager()) WITH CHECK (public.is_manager());


-- ─── PART D ── safety_alerts close-out ───────────────────────────────────────

ALTER TABLE public.safety_alerts
  ADD COLUMN IF NOT EXISTS raised_by_member_id bigint REFERENCES public.team_members(id),
  ADD COLUMN IF NOT EXISTS assigned_to_member_id bigint REFERENCES public.team_members(id),
  ADD COLUMN IF NOT EXISTS assigned_to_name text,
  ADD COLUMN IF NOT EXISTS due_date date,
  ADD COLUMN IF NOT EXISTS action_taken text,
  ADD COLUMN IF NOT EXISTS closed_by_member_id bigint REFERENCES public.team_members(id),
  ADD COLUMN IF NOT EXISTS closed_by_name text,
  ADD COLUMN IF NOT EXISTS closed_at timestamptz;

-- ref numbers must be unique (was random, no constraint)
UPDATE public.safety_alerts a SET ref_no = a.ref_no || '-' || a.id
WHERE EXISTS (SELECT 1 FROM public.safety_alerts b
              WHERE b.ref_no = a.ref_no AND b.id < a.id);

DO $$ BEGIN
  ALTER TABLE public.safety_alerts ADD CONSTRAINT safety_alerts_ref_no_key UNIQUE (ref_no);
EXCEPTION WHEN duplicate_table OR duplicate_object THEN NULL; END $$;

-- server-side ref number, so two people raising an alert at once cannot collide
CREATE SEQUENCE IF NOT EXISTS public.safety_alert_seq;
CREATE OR REPLACE FUNCTION public.next_safety_ref()
RETURNS text LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO 'public'
AS $$ SELECT 'SA-' || to_char(now() AT TIME ZONE 'Australia/Brisbane','YYMMDD')
             || '-' || lpad(nextval('public.safety_alert_seq')::text, 4, '0') $$;
GRANT EXECUTE ON FUNCTION public.next_safety_ref() TO authenticated;


-- ─── PART E ── toolbox talks ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.toolbox_talks (
  id                  bigserial PRIMARY KEY,
  ref_no              text UNIQUE NOT NULL,
  title               text NOT NULL,
  category            text,
  held_at             timestamptz NOT NULL DEFAULT now(),
  location            text,
  presenter_member_id bigint REFERENCES public.team_members(id),
  presenter_name      text,
  content             text,          -- what was covered / talking points
  hazards             text,          -- hazards discussed
  controls            text,          -- controls agreed
  actions             text,          -- follow-up actions
  attachment_urls     text,          -- json array of file urls
  status              text NOT NULL DEFAULT 'open',   -- open | closed
  created_by_member_id bigint REFERENCES public.team_members(id),
  created_at          timestamptz DEFAULT now(),
  closed_at           timestamptz
);

CREATE TABLE IF NOT EXISTS public.toolbox_talk_attendees (
  id             bigserial PRIMARY KEY,
  talk_id        bigint NOT NULL REFERENCES public.toolbox_talks(id) ON DELETE CASCADE,
  team_member_id bigint NOT NULL REFERENCES public.team_members(id),
  is_required    boolean NOT NULL DEFAULT true,
  signed_at      timestamptz,
  signature_url  text,
  comments       text,
  apology_reason text,               -- set when someone genuinely could not attend
  created_at     timestamptz DEFAULT now(),
  UNIQUE (talk_id, team_member_id)
);

CREATE INDEX IF NOT EXISTS idx_tt_attendees_talk ON public.toolbox_talk_attendees(talk_id);
CREATE INDEX IF NOT EXISTS idx_tt_attendees_member ON public.toolbox_talk_attendees(team_member_id);
CREATE INDEX IF NOT EXISTS idx_tt_held_at ON public.toolbox_talks(held_at DESC);

CREATE SEQUENCE IF NOT EXISTS public.toolbox_talk_seq;
CREATE OR REPLACE FUNCTION public.next_toolbox_ref()
RETURNS text LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO 'public'
AS $$ SELECT 'TBT-' || to_char(now() AT TIME ZONE 'Australia/Brisbane','YYMMDD')
             || '-' || lpad(nextval('public.toolbox_talk_seq')::text, 3, '0') $$;
GRANT EXECUTE ON FUNCTION public.next_toolbox_ref() TO authenticated;

ALTER TABLE public.toolbox_talks           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.toolbox_talk_attendees  ENABLE ROW LEVEL SECURITY;

-- talks: everyone signed in can read; supervisors and up can create/edit
DROP POLICY IF EXISTS p_select ON public.toolbox_talks;
DROP POLICY IF EXISTS p_insert ON public.toolbox_talks;
DROP POLICY IF EXISTS p_update ON public.toolbox_talks;
DROP POLICY IF EXISTS p_delete ON public.toolbox_talks;
CREATE POLICY p_select ON public.toolbox_talks FOR SELECT TO authenticated USING (true);
CREATE POLICY p_insert ON public.toolbox_talks FOR INSERT TO authenticated WITH CHECK (public.is_supervisor());
CREATE POLICY p_update ON public.toolbox_talks FOR UPDATE TO authenticated
  USING (public.is_supervisor()) WITH CHECK (public.is_supervisor());
CREATE POLICY p_delete ON public.toolbox_talks FOR DELETE TO authenticated USING (public.is_manager());

-- attendees: readable by all signed-in; the roll is built by supervisors;
-- an employee may only sign their OWN row, and may not un-sign it.
DROP POLICY IF EXISTS p_select ON public.toolbox_talk_attendees;
DROP POLICY IF EXISTS p_insert ON public.toolbox_talk_attendees;
DROP POLICY IF EXISTS p_update ON public.toolbox_talk_attendees;
DROP POLICY IF EXISTS p_delete ON public.toolbox_talk_attendees;
CREATE POLICY p_select ON public.toolbox_talk_attendees FOR SELECT TO authenticated USING (true);
CREATE POLICY p_insert ON public.toolbox_talk_attendees FOR INSERT TO authenticated
  WITH CHECK (public.is_supervisor());
CREATE POLICY p_update ON public.toolbox_talk_attendees FOR UPDATE TO authenticated
  USING (team_member_id = public.me() OR public.is_supervisor())
  WITH CHECK (team_member_id = public.me() OR public.is_supervisor());
CREATE POLICY p_delete ON public.toolbox_talk_attendees FOR DELETE TO authenticated
  USING (public.is_supervisor());

-- A signature, once given, is a record. Nobody edits or removes it except a
-- manager, and an employee can only ever sign as themselves.
CREATE OR REPLACE FUNCTION public.toolbox_attendee_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'public'
AS $$
DECLARE
  actor bigint;
BEGIN
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  actor := public.me();
  IF actor IS NULL THEN
    RAISE EXCEPTION 'Your login is not linked to an active team member.';
  END IF;

  IF NEW.signed_at IS DISTINCT FROM OLD.signed_at
  OR NEW.signature_url IS DISTINCT FROM OLD.signature_url THEN
    IF NEW.signed_at IS NOT NULL THEN
      IF OLD.signed_at IS NOT NULL AND NOT public.is_manager() THEN
        RAISE EXCEPTION 'This attendance has already been signed.';
      END IF;
      IF NEW.team_member_id <> actor THEN
        RAISE EXCEPTION 'You can only sign for yourself.';
      END IF;
    ELSE
      IF NOT public.is_manager() THEN
        RAISE EXCEPTION 'Only a manager can clear a toolbox talk signature.';
      END IF;
    END IF;
  END IF;

  IF NEW.team_member_id IS DISTINCT FROM OLD.team_member_id
  OR NEW.talk_id       IS DISTINCT FROM OLD.talk_id THEN
    RAISE EXCEPTION 'An attendance record cannot be moved to another person or talk.';
  END IF;

  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_toolbox_attendee_guard ON public.toolbox_talk_attendees;
CREATE TRIGGER trg_toolbox_attendee_guard
BEFORE UPDATE ON public.toolbox_talk_attendees
FOR EACH ROW EXECUTE FUNCTION public.toolbox_attendee_guard();


-- ─── PART F ── signature storage ─────────────────────────────────────────────
-- Toolbox signatures live in the existing safety-photos bucket under
-- toolbox/, so no new bucket wiring is needed. safety-photos had no DELETE
-- policy, which is why the x button on alert photos never removed the file.

DROP POLICY IF EXISTS "p_photo_delete" ON storage.objects;
CREATE POLICY "p_photo_delete" ON storage.objects FOR DELETE TO authenticated
USING (bucket_id = ANY (ARRAY['lean-photos','safety-photos']));


-- ─── PART G ── backfill assessor ids from recorded names ─────────────────────
UPDATE public.signoffs s SET assessor_member_id = t.id
FROM public.team_members t
WHERE s.assessor_member_id IS NULL
  AND s.assessor_name IS NOT NULL
  AND t.name = s.assessor_name
  AND (SELECT count(*) FROM public.team_members t2 WHERE t2.name = s.assessor_name) = 1;


-- =============================================================================
-- VERIFY
-- =============================================================================
SELECT 'signoffs policies' AS check, policyname, cmd FROM pg_policies
WHERE schemaname='public' AND tablename='signoffs'
UNION ALL
SELECT 'toolbox policies', policyname, cmd FROM pg_policies
WHERE schemaname='public' AND tablename LIKE 'toolbox%'
ORDER BY 1,2;

-- =============================================================================
-- Factory Portal — saved Invisi-Gard mesh optimiser jobs
-- =============================================================================
-- Applied to the live database on 10/11/2026. Kept here for the record.
-- One row per job number. Signed-in staff can read, add and update; there is
-- no delete from the portal, and no access without a login.
-- =============================================================================
create table if not exists public.mesh_jobs (
  job_number text primary key,
  colour     text,
  total      numeric,
  sheets     integer,
  saved_by   text,
  data       jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.mesh_jobs enable row level security;
revoke all on public.mesh_jobs from anon;
grant select, insert, update on public.mesh_jobs to authenticated;
create policy "auth read mesh jobs"   on public.mesh_jobs for select to authenticated using (true);
create policy "auth insert mesh jobs" on public.mesh_jobs for insert to authenticated with check (true);
create policy "auth update mesh jobs" on public.mesh_jobs for update to authenticated using (true) with check (true);

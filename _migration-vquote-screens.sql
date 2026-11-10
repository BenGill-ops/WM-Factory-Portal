-- =============================================================================
-- Factory Portal — Invisi-Gard screens mirrored from vQuote
-- =============================================================================
-- Applied to the live database on 10/11/2026. Kept here for the record.
-- Filled every 15 minutes by esp-sync\vquote-screens-sync.ps1 on the office
-- sync machine (service key). Signed-in staff can read; nobody else can, and
-- staff cannot change it from the portal.
-- =============================================================================
create table if not exists public.vquote_screens (
  id           text primary key,          -- vQuote item id + frame instance
  quote_num    integer,
  job_num      text,
  quote_title  text,
  pos          integer,                   -- item number on the quote
  item_descr   text,
  kind         text,                      -- 'door' or 'window'
  screen_type  text,
  mesh         text,
  midrail      text,
  finish       text,
  height_mm    integer,
  width_mm     integer,
  qty          integer,
  synced_at    timestamptz not null default now()
);
create index if not exists vquote_screens_quote_idx on public.vquote_screens (quote_num);
create index if not exists vquote_screens_job_idx on public.vquote_screens (job_num);
alter table public.vquote_screens enable row level security;
revoke all on public.vquote_screens from anon;
revoke insert, update, delete, truncate on public.vquote_screens from authenticated;
grant select on public.vquote_screens to authenticated;
create policy "auth read vquote screens" on public.vquote_screens for select to authenticated using (true);

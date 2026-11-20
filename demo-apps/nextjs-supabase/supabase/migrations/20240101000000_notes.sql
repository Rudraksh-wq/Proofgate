-- Base schema. Row-level security is decided by the RLS variant migration (supabase/variants/),
-- installed as 20240201000000_rls_variant.sql by `npm run variant -- A|B|C`.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null default '',
  body text not null default '',
  created_at timestamptz not null default now()
);

create index notes_user_id_idx on public.notes (user_id);

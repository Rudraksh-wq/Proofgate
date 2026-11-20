-- Tenant table: a row belongs to an organisation and every member of it may use the row.
-- Example: `projects` rows carry an org_id; `org_members` says which user belongs to which organisation.
-- Replace the table and column names with the ones in your schema. Add this as a NEW migration file.
create table if not exists public.org_members (
  org_id uuid not null,
  user_id uuid not null references auth.users (id) on delete cascade,
  primary key (org_id, user_id)
);

alter table public.org_members enable row level security;

create policy "members_see_their_own_memberships" on public.org_members
  for select using (auth.uid() = user_id);

alter table public.projects enable row level security;

create policy "projects_select_members" on public.projects
  for select using (
    exists (select 1 from public.org_members m where m.org_id = projects.org_id and m.user_id = auth.uid())
  );

create policy "projects_insert_members" on public.projects
  for insert with check (
    exists (select 1 from public.org_members m where m.org_id = projects.org_id and m.user_id = auth.uid())
  );

create policy "projects_update_members" on public.projects
  for update using (
    exists (select 1 from public.org_members m where m.org_id = projects.org_id and m.user_id = auth.uid())
  ) with check (
    exists (select 1 from public.org_members m where m.org_id = projects.org_id and m.user_id = auth.uid())
  );

create policy "projects_delete_members" on public.projects
  for delete using (
    exists (select 1 from public.org_members m where m.org_id = projects.org_id and m.user_id = auth.uid())
  );

-- Variant B: "role instead of ownership". RLS is on, but every policy only asks whether the caller is
-- signed in (auth.role() = 'authenticated'), never whose row it is. Any signed-in user sees every note.
alter table public.notes enable row level security;

create policy "notes_select_authenticated" on public.notes
  for select using (auth.role() = 'authenticated');

create policy "notes_insert_authenticated" on public.notes
  for insert with check (auth.role() = 'authenticated');

create policy "notes_update_authenticated" on public.notes
  for update using (auth.role() = 'authenticated') with check (auth.role() = 'authenticated');

create policy "notes_delete_authenticated" on public.notes
  for delete using (auth.role() = 'authenticated');

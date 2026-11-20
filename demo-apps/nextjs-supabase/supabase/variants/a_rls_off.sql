-- Variant A: row-level security is OFF on public.notes (the CVE-2025-48757 pattern).
-- Anyone holding the public anon key can read, change and delete every row.
alter table public.notes disable row level security;

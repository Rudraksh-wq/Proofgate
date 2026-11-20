-- PLANTED FLAW (layers 5, 8): a SECURITY DEFINER function that runs whatever SQL text it is given.
-- It runs as its owner, so it skips row-level security, and anyone with the anon key can call it.
-- Local demo only. NEVER deploy anything like this.
create or replace function public.run_sql(query text)
returns jsonb
language plpgsql
security definer
as $$
declare
  result jsonb;
begin
  execute format('select coalesce(jsonb_agg(t), ''[]''::jsonb) from (%s) t', query) into result;
  return result;
end;
$$;

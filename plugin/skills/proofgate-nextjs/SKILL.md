---
name: proofgate-nextjs
description: Use when writing Next.js route handlers (app/**/route.ts), server actions, middleware or API routes that read or write user data. Explains the ownership-check pattern and why authentication must not live only in middleware.ts.
allowed-tools: mcp__plugin_proofgate_proofgate__scan_file mcp__plugin_proofgate_proofgate__scan_project mcp__plugin_proofgate_proofgate__prove mcp__plugin_proofgate_proofgate__verify_fix
---

# Next.js route handlers that pass ProofGate

Every route handler or server action that touches user data does **both** checks itself:

1. **Who is calling?** Create the request-scoped Supabase client (`createServer()` from `lib/supabase/server.ts`, or the template in the `proofgate-supabase` skill) and call `supabase.auth.getUser()`. Return 401 if there is no user.
2. **Does this row belong to them?** Query with the same client (so RLS applies) **and** filter by the owner: `.eq("id", id).eq("user_id", user.id)`. Return 404, not 403, when the row is not theirs.

```ts
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const supabase = createServer();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "not signed in" }, { status: 401 });
  const { data, error } = await supabase.from("notes").select("*").eq("id", params.id).eq("user_id", user.id).single();
  if (error) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json(data);
}
```

## Do not

- **Do not rely on `middleware.ts` alone for authentication.** A crafted request can skip middleware (CVE-2025-29927). Check the user inside the handler too.
- **Do not use the `service_role` client in a route handler.** It skips row-level security, so a missing ownership check becomes a data leak. If a handler truly needs it, it must check ownership by hand and say why.
- Do not build SQL from the query string (`supabase.rpc("run_sql", { query: \`...${q}\` })`). Pass values as parameters.
- Do not return the protected row inside an error body.
- Do not read secrets through a `NEXT_PUBLIC_` variable: those are sent to every visitor's browser.

Never run `proofgate accept` or edit `.proofgate/accepted.yml` to get past a finding: only the user may accept a risk.

When ProofGate proves a route leaks, write the smallest change (usually the two lines above), call `verify_fix`, and keep the regression test it generates.

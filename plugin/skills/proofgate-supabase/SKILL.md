---
name: proofgate-supabase
description: Use when writing Supabase row-level security policies, migrations, database functions or Supabase clients. Gives the correct RLS patterns (owner and tenant), the request-scoped server client, and the rules for migrations that ProofGate's tournament enforces.
allowed-tools: mcp__plugin_proofgate_proofgate__get_contract mcp__plugin_proofgate_proofgate__scan_project mcp__plugin_proofgate_proofgate__prove mcp__plugin_proofgate_proofgate__verify_fix
---

# Supabase patterns that pass ProofGate

Every table in `public` that holds user data needs row-level security **on**, and policies that compare the signed-in user to the row's owner.

**Owner tables** (one user owns each row): copy `${CLAUDE_SKILL_DIR}/templates/rls_owner.sql`. Replace `notes` and `user_id` with the table and owner column named in the contract.

**Tenant tables** (a row belongs to an organisation and members share it): copy `${CLAUDE_SKILL_DIR}/templates/rls_tenant.sql`.

**Route handlers and server code** must use the request-scoped client in `${CLAUDE_SKILL_DIR}/templates/ssr_client.ts`, which acts as the signed-in user so RLS applies. Never use the `service_role` key in a route handler, a client component, or any variable whose name starts with `NEXT_PUBLIC_`.

## Rules ProofGate enforces

- Policies must compare `auth.uid()` to the owner column. `auth.role() = 'authenticated'` alone lets any signed-in user in. `using (true)` on a table the contract says is owned lets everyone in. `auth.uid() is null` lets anonymous visitors in.
- Policies for the same action are combined with **OR**: one weak policy cancels the strong one next to it. Delete weak policies, do not add strong ones beside them.
- **Add a new migration file for every change. Never edit an old migration**: applied migrations are history, and a fix that edits one is rejected.
- A `SECURITY DEFINER` function runs with its owner's rights and skips RLS. Avoid it in `public`; if you must, `revoke execute ... from public, anon`.
- A view skips RLS unless created `with (security_invoker = true)`.
- Never put the `service_role` key in code, a bundle, or a `NEXT_PUBLIC_` variable.

After writing policies, run `scan_project` and `prove`. A fix is accepted only if the second user is still locked out **and** the owner can still read, create, update and delete their own rows - `using (false)` is rejected for that reason.

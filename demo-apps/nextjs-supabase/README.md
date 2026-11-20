# Private notes: ProofGate live demo app (Next.js + Supabase)

**Deliberately vulnerable. Runs only against a local `supabase start`. Never deploy it, never point it at a hosted project.**

A small "private notes" app built the way AI app builders build them: the browser talks to Supabase with the public
anon key and relies on row-level security (RLS) to keep people out of each other's notes.

## Three database variants

| Variant | `public.notes` | What an attacker gets |
|---|---|---|
| **A** | RLS **off** (the CVE-2025-48757 pattern) | anyone with the anon key reads and writes every note |
| **B** | RLS on, policies use `auth.role() = 'authenticated'` | any signed-in user reads and writes every note |
| **C** | RLS on, policies use `auth.uid() = user_id` | nothing: this is the correct one |

Switch with `make reset-demo VARIANT=B` (or `npm run reset-demo -- B`). It copies the variant to
`supabase/migrations/20240201000000_rls_variant.sql` (git-ignored) and replays every migration with `supabase db reset`.

## Other planted flaws (one per ProofGate layer)

| Where | Flaw | Layer |
|---|---|---|
| `package.json` | `lodash@4.17.15`, a version with known vulnerabilities | 3 |
| `lib/admin-client.ts` + `app/notes-client.tsx` | a `service_role` key under a `NEXT_PUBLIC_` name, so it ships in the browser bundle | 2, 6, 9 |
| `next.config.mjs` | `productionBrowserSourceMaps: true` | 9 |
| `app/api/notes/[id]/route.ts` | checks you are signed in, then uses the `service_role` client with no ownership check | 2, 8 |
| `app/api/search/route.ts` + `run_sql()` | SQL built from the query string; `SECURITY DEFINER` function; no auth check | 2, 5, 8 |
| `middleware.ts` | the only login check for `/api/*` lives here (CVE-2025-29927 lesson) | 2 |

## Run it

```
supabase start                 # pulls images the first time (slow); needs Docker
cp .env.example .env.local     # fill the values from `supabase status`
npm install
make reset-demo VARIANT=A      # install a variant and replay the migrations
npm run dev                    # http://localhost:3000
```

Status of this folder: `npm install`, `tsc --noEmit` and `next build` pass, and the SQL parses with the Postgres
parser (pglast). The live run against `supabase start` is **pending real-tool verification** (it needs a running
Docker daemon and the Supabase CLI).

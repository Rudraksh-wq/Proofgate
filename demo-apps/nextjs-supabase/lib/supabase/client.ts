import { createBrowserClient } from "@supabase/ssr";

// Browser client: public URL + public anon key. Safe to ship, as long as RLS is correct.
export function createClient() {
  return createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
}

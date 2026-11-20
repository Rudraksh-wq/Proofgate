// PLANTED FLAW (layers 2, 6, 9): this file is imported by a client component, and the key it reads has a
// NEXT_PUBLIC_ name, so Next.js copies the service_role key into the JavaScript bundle sent to every visitor.
// A service_role key skips ALL row-level security. Rotate such a key immediately if it was ever shipped.
import { createClient } from "@supabase/supabase-js";

export const adminClient = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
);

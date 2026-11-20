import { createClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";

// PLANTED FLAWS (layers 2, 5, 8):
//  * SQL is built from the query string and run through the run_sql() database function (SQL injection);
//  * run_sql is SECURITY DEFINER, so it runs as its owner and skips RLS;
//  * there is no login check here: it trusts middleware.ts.
const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? "";
  const { data, error } = await supabase.rpc("run_sql", {
    query: `select id, title, body from public.notes where title ilike '%${q}%'`,
  });
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json(data);
}

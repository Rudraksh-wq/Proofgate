import { createClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";
import { createServer } from "@/lib/supabase/server";

// PLANTED FLAW (layers 2, 8): this handler checks that SOMEONE is signed in, then reads and writes with the
// service_role client, which skips RLS. It never checks that the note belongs to the caller, so any signed-in
// user can read or change any note by id (broken object-level authorization).
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const {
    data: { user },
  } = await createServer().auth.getUser();
  if (!user) return NextResponse.json({ error: "not signed in" }, { status: 401 });
  const { data, error } = await admin.from("notes").select("*").eq("id", params.id).single();
  if (error) return NextResponse.json({ error: error.message }, { status: 404 });
  return NextResponse.json(data);
}

export async function PUT(req: Request, { params }: { params: { id: string } }) {
  const {
    data: { user },
  } = await createServer().auth.getUser();
  if (!user) return NextResponse.json({ error: "not signed in" }, { status: 401 });
  const { title, body } = await req.json();
  const { data, error } = await admin.from("notes").update({ title, body }).eq("id", params.id).select().single();
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json(data);
}

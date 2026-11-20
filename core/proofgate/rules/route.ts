// Test cases for rules/route.yaml (semgrep --test convention). The file is named route.ts on purpose:
// the rules only apply to Next.js route handlers.
declare const createClient: any, process: any, NextResponse: any, supabase: any;

// ruleid: proofgate.next-route-service-role-client
const admin = createClient("https://x.supabase.invalid", process.env.SUPABASE_SERVICE_ROLE_KEY);
// ok: proofgate.next-route-service-role-client
const anon = createClient("https://x.supabase.invalid", process.env.SUPABASE_ANON_KEY);

// ruleid: proofgate.next-route-no-auth-check
export async function GET(req: Request) {
  const { data } = await supabase.from("notes").select("*");
  return NextResponse.json(data);
}

// ok: proofgate.next-route-no-auth-check
export async function POST(req: Request) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({}, { status: 401 });
  return NextResponse.json({ ok: true });
}

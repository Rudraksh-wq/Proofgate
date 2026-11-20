// `npm run reset-demo -- [A|B|C]`: install an RLS variant (default A) and replay every migration from scratch
// on the LOCAL Supabase stack (`supabase db reset`). Needs the Supabase CLI and a running `supabase start`.
import { spawnSync } from "node:child_process";
import { setVariant } from "./set-variant.mjs";

try {
  console.log(`variant ${setVariant(process.argv[2] ?? "A")} installed`);
} catch (e) {
  console.error(`error: ${e.message}`);
  process.exit(2);
}

const r = spawnSync("supabase", ["db", "reset"], { stdio: "inherit" });
if (r.error) {
  console.error("error: could not run `supabase db reset`. Install the Supabase CLI and run `supabase start` first.");
  process.exit(2);
}
process.exit(r.status ?? 2);

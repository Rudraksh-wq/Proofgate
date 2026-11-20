// Install one RLS variant as a migration: `npm run variant -- A|B|C`.
// The installed file (supabase/migrations/20240201000000_rls_variant.sql) is git-ignored, so switching never
// dirties the working tree. Replaying all migrations (`supabase db reset`) makes the switch take effect.
import { copyFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const VARIANTS = { A: "a_rls_off.sql", B: "b_auth_role.sql", C: "c_owner_only.sql" };
export const TARGET = join(root, "supabase", "migrations", "20240201000000_rls_variant.sql");

export function setVariant(letter) {
  const key = String(letter ?? "").toUpperCase();
  if (!(key in VARIANTS)) throw new Error(`unknown variant ${JSON.stringify(letter)}; use A, B or C`);
  const src = join(root, "supabase", "variants", VARIANTS[key]);
  if (!existsSync(src)) throw new Error(`missing ${src}`);
  copyFileSync(src, TARGET);
  return key;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    console.log(`variant ${setVariant(process.argv[2] ?? "A")} installed -> ${TARGET}`);
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(2);
  }
}

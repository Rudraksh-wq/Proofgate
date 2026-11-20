// After the build: replace the labelled placeholder https://<site> in the machine-readable files with your real URL.
//   SITE_URL=https://proofgate.example npm run build
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "out");
const site = (process.env.SITE_URL ?? "").replace(/\/+$/, "");
if (!existsSync(out)) process.exit(0);
if (!site) {
  console.log("SITE_URL is not set: llms.txt keeps the labelled placeholder https://<site>. Set SITE_URL when you deploy.");
  process.exit(0);
}
if (!/^https:\/\/[A-Za-z0-9.-]+(:\d+)?(\/[\w./-]*)?$/.test(site)) {
  console.error(`SITE_URL must be a plain https URL, got ${JSON.stringify(site)}`);
  process.exit(2);
}
let changed = 0;
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(txt|md)$/.test(name)) {
      const text = readFileSync(p, "utf8");
      if (text.includes("https://<site>")) {
        writeFileSync(p, text.replaceAll("https://<site>", site));
        changed++;
      }
    }
  }
};
walk(out);
console.log(`SITE_URL applied to ${changed} file(s)`);

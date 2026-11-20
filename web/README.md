# ProofGate website

A **static** Next.js site: the home page, `/install`, `/how-it-works`, `/limits`, `/benchmark`, plus `llms.txt` and `llms-full.txt`.
It has no API routes, no forms, no accounts, no uploads, no analytics and no backend. It never scans, uploads or stores code.

```
cd web
npm install
npm run build                       # writes plain files to web/out/
SITE_URL=https://your.site npm run build   # also fills in the https://<site> placeholder in llms.txt
npm run dev                         # http://localhost:3001
```

`prebuild` generates `llms-full.txt`, `limits.md`, `benchmark.md`, `docs/*.md` and `schemas/*.json` from the repository's own sources
(the MCP server's docstrings, the main skill, the JSON schemas, `bench/results.json`), so the documentation cannot drift from the product.
The benchmark page shows only what `bench/results.json` contains.

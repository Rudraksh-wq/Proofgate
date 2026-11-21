# ProofGate static website

Astro + Tailwind CSS static starter for the ProofGate marketing and install site. It contains no server endpoints, API routes, analytics, or code submission forms.

## Requirements

- Node.js 18.17+ (Node 20 LTS recommended)
- npm

## Run locally

```sh
npm install
npm run dev
```

Astro prints the local URL, usually `http://localhost:4321`.

## Build and preview

```sh
npm run build
npm run preview
```

The static site is generated in `dist/`. Deploy that directory to any static host.

## Structure

- `src/pages/` — static routes
- `src/layouts/` — shared page shell
- `src/components/` — Navbar, Footer, Button, Card, Badge, CodeBlock, Section
- `src/styles/global.css` — base styles and Neo-Brutalist utilities
- `tailwind.config.mjs` — colors, fonts, and hard-shadow tokens

## Backend source of truth

The ProofGate implementation is in the adjacent `Proofgate/` folder. The frontend benchmark snapshot is copied to `src/data/results.json` from `Proofgate/bench/results.json`; refresh it after re-running the backend benchmark with `python bench/run_bench.py` from the `Proofgate/` folder. Review the benchmark corpus limits before quoting its numbers.

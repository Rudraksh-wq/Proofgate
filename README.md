# ProofGate

A local security gate for the AI coding loop. It runs 9 layers of checks, proves
access-control bugs by attacking your app as a second user on a throwaway local
database, and only accepts a fix when the same attack fails and the owner's
feature still works.

> Status: under construction. See `docs/PROOFGATE_FINAL_PLAN.md`.

## Develop

```
python -m venv .venv
.venv/Scripts/pip install -e "core[dev]"      # Windows; use .venv/bin/pip elsewhere
.venv/Scripts/python -m pytest -q
```

Passing ProofGate means our attacks failed on the routes and tables we tested.
It does not mean your app is secure.

"""Generate the ProofGate Flask benchmark corpus (Master Guide P3, plan 14).

    python demo-apps/generate_corpus.py            # (re)write apps, fixes, ground truth
    python demo-apps/generate_corpus.py --check-registry   # also confirm the fake package is 404 (needs network)

16 apps in demo-apps/flask-corpus/ (3 clean/bait + 13 with one planted flaw) and 12 candidate fixes
(correct / lazy / partial for v01, v05, v06, v07) in demo-apps/flask-fixes/.

Every secret below is RANDOM AND FAKE, derived from a fixed seed so regeneration is byte-stable.
These are deliberately vulnerable synthetic apps. Never deploy them.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "flask-corpus"
FIXES = HERE / "flask-fixes"
FAKE_PACKAGE = "flask-notes-sanitizer-pgx7k2"  # must be 404 on PyPI (see registry_check.json)

PROMPT = """Build a private notes app with Flask and SQLite.

- People can sign up and log in. Signing up returns an API token (sent as `Authorization: Bearer <token>`).
- Each person has their own private notes: create, read, update, delete, list and search them.
- A person can edit their own display name.
- An admin can list all users.
- Users must never be able to see or change each other's notes.
- The server reads PORT and DB_PATH from the environment.
"""

# ----------------------------------------------------------------------------- template
BASE = '''"""Notes API: ProofGate corpus app @@NAME@@. Synthetic benchmark target, do not deploy."""
import os
import secrets
import sqlite3
@@IMPORTS@@
from flask import Flask, abort, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "notes.db"))
USER_COLUMNS = ("display_name", "role", "is_admin")
@@CONSTANTS@@
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    is_admin INTEGER NOT NULL DEFAULT 0,
    token TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT ''
);
"""


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return db().execute("SELECT * FROM users WHERE token = ?", (header[7:],)).fetchone()


def login_required():
    user = current_user()
    if user is None:
        abort(401)
    return user


def _is_admin(user):
    return user["role"] == "admin" or bool(user["is_admin"])


def _note_json(row):
    return {"id": row["id"], "owner_id": row["owner_id"], "title": row["title"], "body": row["body"]}


def _profile_json(row):
    return {
        "id": row["id"], "email": row["email"], "display_name": row["display_name"],
        "role": row["role"], "is_admin": bool(row["is_admin"]),
    }
@@HELPERS@@

@app.post("/signup")
def signup():
    data = request.get_json(silent=True) or {}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify(error="email and password required"), 400
    token = secrets.token_hex(16)
    try:
        cur = db().execute(
            "INSERT INTO users (email, password_hash, display_name, role, is_admin, token) "
            "VALUES (?, ?, ?, 'user', 0, ?)",
            (email, generate_password_hash(password), data.get("display_name", ""), token),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="email already registered"), 409
    return jsonify(id=cur.lastrowid, token=token), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    row = db().execute("SELECT * FROM users WHERE email = ?", (data.get("email"),)).fetchone()
    if row is None or not check_password_hash(row["password_hash"], data.get("password") or ""):
        return jsonify(error="invalid credentials"), 401
    return jsonify(id=row["id"], token=row["token"])


@app.get("/notes")
def list_notes():
    user = login_required()
@@LIST_BODY@@

@app.post("/notes")
def create_note():
    user = login_required()
    data = request.get_json(silent=True) or {}
    cur = db().execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], data.get("title", ""), data.get("body", "")),
    )
    db().commit()
    row = db().execute("SELECT * FROM notes WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(_note_json(row)), 201


@app.get("/notes/<int:note_id>")
def get_note(note_id):
    user = login_required()
@@GET_LOOKUP@@
    return jsonify(_note_json(note))


@app.put("/notes/<int:note_id>")
def update_note(note_id):
    user = login_required()
@@PUT_LOOKUP@@
    data = request.get_json(silent=True) or {}
    db().execute(
        "UPDATE notes SET title = ?, body = ? WHERE id = ?",
        (data.get("title", note["title"]), data.get("body", note["body"]), note_id),
    )
    db().commit()
    row = db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    return jsonify(_note_json(row))


@app.delete("/notes/<int:note_id>")
def delete_note(note_id):
    user = login_required()
@@DEL_LOOKUP@@
    db().execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db().commit()
    return jsonify(deleted=note_id)


@app.get("/search")
def search_notes():
    user = login_required()
@@SEARCH_BODY@@

@app.get("/export")
def export_note_name():
    login_required()
@@EXPORT_BODY@@

@app.get("/profile")
def get_profile():
    user = login_required()
    return jsonify(_profile_json(user))


@app.put("/profile")
def update_profile():
@@PROFILE_BODY@@

@app.get("/admin/users")
def admin_users():
@@ADMIN_GUARD@@    rows = db().execute("SELECT id, email, display_name, role FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=@@DEBUG@@, use_reloader=False)
'''

# ----------------------------------------------------------------------------- snippets
LOOKUP = '    note = db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()\n'
CHECK_OWNER = '    if note is None or note["owner_id"] != user["id"]:\n        abort(404)\n'
CHECK_EXISTS = '    if note is None:\n        abort(404)\n'
LOOKUP_SAFE = LOOKUP + CHECK_OWNER
LOOKUP_UNSAFE = LOOKUP + CHECK_EXISTS
LOOKUP_HELPER = "    note = _owned_note_or_404(note_id, user)\n"

HELPER_OWNED = '''

def _owned_note_or_404(note_id, user):
    note = db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None or note["owner_id"] != user["id"]:
        abort(404)
    return note
'''

LIST_SAFE = (
    '    rows = db().execute("SELECT * FROM notes WHERE owner_id = ? ORDER BY id", (user["id"],)).fetchall()\n'
    "    return jsonify([_note_json(r) for r in rows])\n"
)
LIST_PARAM = (
    '    owner_id = request.args.get("user_id", user["id"])\n'
    '    rows = db().execute("SELECT * FROM notes WHERE owner_id = ? ORDER BY id", (owner_id,)).fetchall()\n'
    "    return jsonify([_note_json(r) for r in rows])\n"
)
LIST_ALLOWLISTED = (  # c03 bait: f-string SQL, but the interpolated value comes from a fixed allow-list
    '    order = ORDER_COLUMNS.get(request.args.get("sort", "id"), "id")\n'
    '    rows = db().execute(f"SELECT * FROM notes WHERE owner_id = ? ORDER BY {order}", (user["id"],)).fetchall()\n'
    "    return jsonify([_note_json(r) for r in rows])\n"
)

SEARCH_SAFE = (
    '    q = request.args.get("q", "")\n'
    "    rows = db().execute(\n"
    '        "SELECT * FROM notes WHERE owner_id = ? AND title LIKE ?", (user["id"], f"%{q}%")\n'
    "    ).fetchall()\n"
    "    return jsonify([_note_json(r) for r in rows])\n"
)
_SQLI_TAIL = (
    "    rows = db().execute(\n"
    "        f\"SELECT * FROM notes WHERE owner_id = {user['id']} AND title LIKE '%{q}%'\"\n"
    "    ).fetchall()\n"
    "    return jsonify([_note_json(r) for r in rows])\n"
)
SEARCH_SQLI = '    q = request.args.get("q", "")\n' + _SQLI_TAIL
SEARCH_SQLI_PARTIAL = (
    '    q = request.args.get("q", "").replace("--", "").replace(";", "")\n' + _SQLI_TAIL
)
SEARCH_LAZY = '    return jsonify(error="search is disabled"), 403\n'

EXPORT_SAFE = '    return jsonify(name=request.args.get("name", "notes"))\n'
EXPORT_CMDI = (
    "    import subprocess\n\n"
    '    name = request.args.get("name", "notes")\n'
    '    out = subprocess.run(f"echo {name}", shell=True, capture_output=True, text=True).stdout\n'
    "    return jsonify(result=out.strip())\n"
)

PROFILE_SAFE = (
    "    user = login_required()\n"
    "    data = request.get_json(silent=True) or {}\n"
    '    if "display_name" in data:\n'
    '        db().execute("UPDATE users SET display_name = ? WHERE id = ?", (data["display_name"], user["id"]))\n'
    "        db().commit()\n"
    '    row = db().execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()\n'
    "    return jsonify(_profile_json(row))\n"
)


def _profile_mass(condition: str) -> str:
    return (
        "    user = login_required()\n"
        "    data = request.get_json(silent=True) or {}\n"
        "    for key, value in data.items():\n"
        f"        if {condition}:\n"
        '            db().execute(f"UPDATE users SET {key} = ? WHERE id = ?", (value, user["id"]))\n'
        "    db().commit()\n"
        '    row = db().execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()\n'
        "    return jsonify(_profile_json(row))\n"
    )


PROFILE_MASS = _profile_mass("key in USER_COLUMNS")
PROFILE_PARTIAL = _profile_mass('key in USER_COLUMNS and key != "is_admin"')
PROFILE_LAZY = "    login_required()\n    return jsonify(error=\"profile updates are disabled\"), 403\n"

ADMIN_SAFE = "    user = login_required()\n    if not _is_admin(user):\n        abort(403)\n"
ADMIN_NOROLE = "    login_required()\n"
ADMIN_NOAUTH = ""
ADMIN_LAZY = "    abort(403)\n"
ADMIN_PARTIAL = '    if "Authorization" not in request.headers:\n        abort(401)\n'

GET_PARTIAL = (
    LOOKUP + CHECK_EXISTS
    + '    if note["owner_id"] != user["id"]:\n'
    '        return jsonify(error="forbidden", note=_note_json(note)), 403\n'
)
GET_LAZY = '    abort(403)\n    note = None\n'

DEFAULTS = {
    "IMPORTS": "", "CONSTANTS": "", "HELPERS": "", "DEBUG": "False",
    "LIST_BODY": LIST_SAFE, "GET_LOOKUP": LOOKUP_SAFE, "PUT_LOOKUP": LOOKUP_SAFE, "DEL_LOOKUP": LOOKUP_SAFE,
    "SEARCH_BODY": SEARCH_SAFE, "EXPORT_BODY": EXPORT_SAFE, "PROFILE_BODY": PROFILE_SAFE,
    "ADMIN_GUARD": ADMIN_SAFE,
}


# ----------------------------------------------------------------------------- fake secrets
# Secret-shaped strings are NEVER committed (GitHub push protection, and our own secret scan, must stay
# clean). Files that need them are committed as *.tmpl with {{PLACEHOLDERS}}; `materialize()` renders the
# real files at run time with fresh random fakes, and those files are git-ignored.
def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def fake_jwt(role: str) -> str:
    payload = {"iss": "supabase", "ref": secrets.token_hex(10), "role": role, "iat": 1700000000, "exp": 2000000000}
    sig = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    return f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(payload)}.{sig}"


def fake_stripe() -> str:
    return "sk_" + "live_" + secrets.token_hex(12)


def fake_values() -> dict[str, str]:
    return {
        "FAKE_STRIPE_KEY": fake_stripe(),
        "FAKE_SERVICE_ROLE_JWT": fake_jwt("service_role"),
        "FAKE_ANON_JWT": fake_jwt("anon"),
    }


# generated, git-ignored files (relative to the app dir); each has a committed <name>.tmpl
SECRET_FILES = {
    "v09_hardcoded_keys": ["app.py"],
    "c03_bait": ["app.py"],
    "v10_service_role_in_bundle": ["static/bundle.js"],
}
TMPL = ".tmpl"


# ----------------------------------------------------------------------------- app specs
def app_specs() -> dict[str, dict]:
    """name -> {overrides, requirements, truth, extra_files}. One planted flaw each (c* have none)."""
    reqs = ["Flask>=3.0"]
    specs: dict[str, dict] = {
        "c01_clean": {"truth": []},
        "c02_clean_helper": {
            "set": {
                "HELPERS": HELPER_OWNED, "GET_LOOKUP": LOOKUP_HELPER, "PUT_LOOKUP": LOOKUP_HELPER,
                "DEL_LOOKUP": LOOKUP_HELPER,
            },
            "truth": [],
        },
        "c03_bait": {
            "set": {
                "CONSTANTS": (
                    "# Looks scary, is fine: a public anon key (role=anon), a placeholder, and an allow-listed ORDER BY.\n"
                    'SUPABASE_ANON_KEY = "{{FAKE_ANON_JWT}}"\n'
                    'API_KEY = "changeme"\n'
                    'ORDER_COLUMNS = {"id": "id", "title": "title"}\n'
                ),
                "LIST_BODY": LIST_ALLOWLISTED,
            },
            "truth": [],
        },
        "v01_idor_read": {
            "set": {"GET_LOOKUP": LOOKUP_UNSAFE},
            "truth": [{"category": "access", "cwe": "CWE-639", "label": "cross-user-read"}],
        },
        "v02_idor_write": {
            "set": {"PUT_LOOKUP": LOOKUP_UNSAFE},
            "truth": [{"category": "access", "cwe": "CWE-639", "label": "cross-user-write"}],
        },
        "v03_idor_param": {
            "set": {"LIST_BODY": LIST_PARAM},
            "truth": [{"category": "access", "cwe": "CWE-639", "label": "list-by-user-id-param"}],
        },
        "v04_missing_role": {
            "set": {"ADMIN_GUARD": ADMIN_NOROLE},
            "truth": [{"category": "access", "cwe": "CWE-862", "label": "admin-route-missing-role-check"}],
        },
        "v05_unauth_admin": {
            "set": {"ADMIN_GUARD": ADMIN_NOAUTH},
            "truth": [{"category": "access", "cwe": "CWE-306", "label": "admin-route-unauthenticated"}],
        },
        "v06_mass_assign": {
            "set": {"PROFILE_BODY": PROFILE_MASS},
            "truth": [{"category": "access", "cwe": "CWE-915", "label": "mass-assignment-role"}],
        },
        "v07_sqli": {
            "set": {"SEARCH_BODY": SEARCH_SQLI},
            "truth": [{"category": "injection", "cwe": "CWE-89", "label": "sql-injection-search"}],
        },
        "v08_cmdi": {
            "set": {"EXPORT_BODY": EXPORT_CMDI},
            "truth": [{"category": "injection", "cwe": "CWE-78", "label": "shell-injection-export"}],
        },
        "v09_hardcoded_keys": {
            "set": {
                "CONSTANTS": (
                    'STRIPE_SECRET_KEY = "{{FAKE_STRIPE_KEY}}"\n'
                    'SUPABASE_SERVICE_ROLE_KEY = "{{FAKE_SERVICE_ROLE_JWT}}"\n'
                ),
            },
            "truth": [
                {"category": "secrets", "cwe": "CWE-798", "label": "hardcoded-stripe-live-key"},
                {"category": "secrets", "cwe": "CWE-798", "label": "hardcoded-service-role-key"},
            ],
        },
        "v10_service_role_in_bundle": {
            "files": {
                "static/bundle.js": (
                    "// built bundle (synthetic)\n"
                    'const SUPABASE_URL = "https://example-project.supabase.invalid";\n'
                    'const SUPABASE_KEY = "{{FAKE_SERVICE_ROLE_JWT}}";\n'
                    "window.client = { url: SUPABASE_URL, key: SUPABASE_KEY };\n"
                    "//# sourceMappingURL=bundle.js.map\n"
                ),
                "static/bundle.js.map": json.dumps(
                    {"version": 3, "file": "bundle.js", "sources": ["src/client.js"], "mappings": ""}
                ) + "\n",
            },
            "truth": [{"category": "bundle", "cwe": "CWE-798", "label": "service-role-key-in-frontend-bundle"}],
        },
        "v11_hallucinated_dep": {
            "requirements": reqs + [FAKE_PACKAGE + "==1.0.0"],
            "truth": [{"category": "supply-chain", "cwe": "CWE-829", "label": "nonexistent-package-in-requirements"}],
        },
        "v12_outdated_dep": {
            "requirements": reqs + ["requests==2.19.0"],
            "truth": [{"category": "deps", "cwe": "CWE-1395", "label": "requests-2.19.0-known-vulnerabilities"}],
        },
        "v13_debug_tls": {
            "set": {
                "DEBUG": "True",
                "HELPERS": (
                    "\n\ndef _ping_upstream(url):\n"
                    '    """Health-check an upstream service. Never called at startup."""\n'
                    "    import requests\n\n"
                    "    return requests.get(url, verify=False, timeout=3)\n"
                ),
            },
            "truth": [
                {"category": "config", "cwe": "CWE-489", "label": "flask-debug-true"},
                {"category": "web", "cwe": "CWE-295", "label": "tls-verification-disabled"},
            ],
        },
    }
    for s in specs.values():
        s.setdefault("requirements", reqs)
    return specs


# fix kind -> (app, snippet overrides). Each fixed app = the vulnerable app with ONE snippet replaced.
FIX_SPECS: dict[str, dict] = {
    "v01_correct": {"app": "v01_idor_read", "kind": "correct", "set": {"GET_LOOKUP": LOOKUP_SAFE}},
    "v01_lazy": {"app": "v01_idor_read", "kind": "lazy", "set": {"GET_LOOKUP": GET_LAZY}},
    "v01_partial": {"app": "v01_idor_read", "kind": "partial", "set": {"GET_LOOKUP": GET_PARTIAL}},
    "v05_correct": {"app": "v05_unauth_admin", "kind": "correct", "set": {"ADMIN_GUARD": ADMIN_SAFE}},
    "v05_lazy": {"app": "v05_unauth_admin", "kind": "lazy", "set": {"ADMIN_GUARD": ADMIN_LAZY}},
    "v05_partial": {"app": "v05_unauth_admin", "kind": "partial", "set": {"ADMIN_GUARD": ADMIN_PARTIAL}},
    "v06_correct": {"app": "v06_mass_assign", "kind": "correct", "set": {"PROFILE_BODY": PROFILE_SAFE}},
    "v06_lazy": {"app": "v06_mass_assign", "kind": "lazy", "set": {"PROFILE_BODY": PROFILE_LAZY}},
    "v06_partial": {"app": "v06_mass_assign", "kind": "partial", "set": {"PROFILE_BODY": PROFILE_PARTIAL}},
    "v07_correct": {"app": "v07_sqli", "kind": "correct", "set": {"SEARCH_BODY": SEARCH_SAFE}},
    "v07_lazy": {"app": "v07_sqli", "kind": "lazy", "set": {"SEARCH_BODY": SEARCH_LAZY}},
    "v07_partial": {"app": "v07_sqli", "kind": "partial", "set": {"SEARCH_BODY": SEARCH_SQLI_PARTIAL}},
}


# label -> (file inside the app dir, text that appears on the offending line). ground_truth.json points at
# file + line, never at a key value. Lines are found in the rendered template, so they are stable.
LOCATE: dict[str, tuple[str, str]] = {
    "cross-user-read": ("app.py", "def get_note"),
    "cross-user-write": ("app.py", "def update_note"),
    "list-by-user-id-param": ("app.py", "def list_notes"),
    "admin-route-missing-role-check": ("app.py", "def admin_users"),
    "admin-route-unauthenticated": ("app.py", "def admin_users"),
    "mass-assignment-role": ("app.py", "def update_profile"),
    "sql-injection-search": ("app.py", "def search_notes"),
    "shell-injection-export": ("app.py", "def export_note_name"),
    "hardcoded-stripe-live-key": ("app.py", "STRIPE_SECRET_KEY"),
    "hardcoded-service-role-key": ("app.py", "SUPABASE_SERVICE_ROLE_KEY"),
    "service-role-key-in-frontend-bundle": ("static/bundle.js", "const SUPABASE_KEY"),
    "nonexistent-package-in-requirements": ("requirements.txt", FAKE_PACKAGE),
    "requests-2.19.0-known-vulnerabilities": ("requirements.txt", "requests==2.19.0"),
    "flask-debug-true": ("app.py", "debug=True"),
    "tls-verification-disabled": ("app.py", "verify=False"),
}


def locate(texts: dict[str, str], label: str) -> dict[str, object]:
    rel, needle = LOCATE[label]
    for i, line in enumerate(texts[rel].splitlines(), start=1):
        if needle in line:
            return {"file": rel, "line": i}
    raise ValueError(f"{label}: {needle!r} not found in {rel}")


def render(name: str, overrides: dict[str, str]) -> str:
    snippets = {**DEFAULTS, **overrides, "NAME": name}
    text = BASE
    for key, value in snippets.items():
        text = text.replace(f"@@{key}@@\n", value if value.endswith("\n") or value == "" else value + "\n")
        text = text.replace(f"@@{key}@@", value)
    assert "@@" not in text, "unfilled template marker"
    return re.sub(r"(?<=[^\n])\n\n(?=@app\.|if __name__)", "\n\n\n", text)  # PEP 8 spacing


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def build(out_corpus: Path = CORPUS, out_fixes: Path = FIXES) -> None:
    specs = app_specs()
    for old in (out_corpus, out_fixes):
        if old.exists():
            for child in old.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
    truth: dict[str, list[dict]] = {}
    for name, spec in specs.items():
        d = out_corpus / name
        texts = {
            "app.py": render(name, spec.get("set", {})),
            "requirements.txt": "\n".join(spec["requirements"]) + "\n",
            "PROMPT.md": PROMPT,
            **spec.get("files", {}),
        }
        secret_files = SECRET_FILES.get(name, [])
        for rel, content in texts.items():
            _write(d / (rel + TMPL if rel in secret_files else rel), content)
        truth[name] = [{**item, **locate(texts, item["label"])} for item in spec["truth"]]
    _write(out_corpus / "ground_truth.json", json.dumps(truth, indent=2) + "\n")
    _write(
        out_corpus / "README.md",
        "# Flask corpus (synthetic)\n\nGenerated by `demo-apps/generate_corpus.py`; do not edit by hand.\n"
        "Deliberately vulnerable benchmark targets with FAKE secrets. Never deploy them.\n"
        "`ground_truth.json` lists the planted flaw(s) per app (`c*` apps have none).\n",
    )
    fixes_meta: dict[str, dict] = {}
    for fname, fx in FIX_SPECS.items():
        base = specs[fx["app"]]
        merged = {**base.get("set", {}), **fx["set"]}
        d = out_fixes / fname
        _write(d / "app.py", render(fname, merged))
        _write(d / "requirements.txt", "\n".join(base["requirements"]) + "\n")
        _write(d / "PROMPT.md", PROMPT)
        fixes_meta[fname] = {"app": fx["app"], "kind": fx["kind"], "should_accept": fx["kind"] == "correct"}
    _write(out_fixes / "fixes.json", json.dumps(fixes_meta, indent=2) + "\n")


def materialize(out_corpus: Path = CORPUS) -> list[Path]:
    """Render every *.tmpl with fresh random fake secrets. The outputs are git-ignored."""
    values = fake_values()
    written = []
    for name, rels in SECRET_FILES.items():
        for rel in rels:
            tmpl = out_corpus / name / (rel + TMPL)
            text = tmpl.read_text(encoding="utf-8")
            for key, value in values.items():
                text = text.replace("{{" + key + "}}", value)
            assert "{{" not in text, f"unfilled placeholder in {tmpl}"
            _write(tmpl.with_suffix(""), text)
            written.append(tmpl.with_suffix(""))
    return written


def check_registry() -> int:
    import datetime as dt

    import httpx

    r = httpx.get(f"https://pypi.org/pypi/{FAKE_PACKAGE}/json", timeout=15)
    result = {
        "package": FAKE_PACKAGE, "registry": "pypi", "status": r.status_code,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    _write(CORPUS / "registry_check.json", json.dumps(result, indent=2) + "\n")
    print(result)
    if r.status_code != 404:
        print(f"ERROR: {FAKE_PACKAGE} exists on PyPI; choose another fake name", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    registry_cache = (CORPUS / "registry_check.json").read_bytes() if (CORPUS / "registry_check.json").exists() else None
    build()
    if registry_cache is not None:
        _write(CORPUS / "registry_check.json", registry_cache.decode("utf-8"))
    generated = materialize()
    print(f"wrote {len(app_specs())} apps and {len(FIX_SPECS)} fixes; rendered {len(generated)} secret-bearing files")
    sys.exit(check_registry() if "--check-registry" in sys.argv else 0)

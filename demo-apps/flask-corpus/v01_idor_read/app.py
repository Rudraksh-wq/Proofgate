"""Notes API: ProofGate corpus app v01_idor_read. Synthetic benchmark target, do not deploy."""
import os
import secrets
import sqlite3
from flask import Flask, abort, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "notes.db"))
USER_COLUMNS = ("display_name", "role", "is_admin")
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
    rows = db().execute("SELECT * FROM notes WHERE owner_id = ? ORDER BY id", (user["id"],)).fetchall()
    return jsonify([_note_json(r) for r in rows])


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
    note = db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None:
        abort(404)
    return jsonify(_note_json(note))


@app.put("/notes/<int:note_id>")
def update_note(note_id):
    user = login_required()
    note = db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None or note["owner_id"] != user["id"]:
        abort(404)
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
    note = db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None or note["owner_id"] != user["id"]:
        abort(404)
    db().execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db().commit()
    return jsonify(deleted=note_id)


@app.get("/search")
def search_notes():
    user = login_required()
    q = request.args.get("q", "")
    rows = db().execute(
        "SELECT * FROM notes WHERE owner_id = ? AND title LIKE ?", (user["id"], f"%{q}%")
    ).fetchall()
    return jsonify([_note_json(r) for r in rows])


@app.get("/export")
def export_note_name():
    login_required()
    return jsonify(name=request.args.get("name", "notes"))


@app.get("/profile")
def get_profile():
    user = login_required()
    return jsonify(_profile_json(user))


@app.put("/profile")
def update_profile():
    user = login_required()
    data = request.get_json(silent=True) or {}
    if "display_name" in data:
        db().execute("UPDATE users SET display_name = ? WHERE id = ?", (data["display_name"], user["id"]))
        db().commit()
    row = db().execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    return jsonify(_profile_json(row))


@app.get("/admin/users")
def admin_users():
    user = login_required()
    if not _is_admin(user):
        abort(403)
    rows = db().execute("SELECT id, email, display_name, role FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False, use_reloader=False)

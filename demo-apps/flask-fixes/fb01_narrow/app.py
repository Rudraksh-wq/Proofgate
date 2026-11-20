import os
import sqlite3
from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "notes.db"))
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, token TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, title TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '');
"""


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


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


init_db()


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


@app.post("/signup")
def signup():
    data = request.get_json(silent=True) or {}
    cur = db().execute("INSERT INTO users (email, token) VALUES (?, ?)", (data.get("email", ""), os.urandom(16).hex()))
    db().commit()
    row = db().execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(id=row["id"], token=row["token"]), 201


@app.post("/api/notes")
def create_note():
    user = login_required()
    data = request.get_json(silent=True) or {}
    cur = db().execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", (user["id"], data.get("title", ""), data.get("body", "")))
    db().commit()
    row = db().execute("SELECT * FROM notes WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(dict(row)), 201


@app.get("/api/notes/<int:id>")
def get_note(id):
    user = login_required()
    note = db().execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
    if note is None or note["owner_id"] != user["id"]:
        abort(404)
    return jsonify(dict(note))


@app.patch("/api/notes/<int:id>")
def patch_note(id):
    user = login_required()
    note = db().execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
    if note is None or note["owner_id"] != user["id"]:
        abort(404)
    data = request.get_json(silent=True) or {}
    db().execute("UPDATE notes SET title = ?, body = ? WHERE id = ?", (data.get("title", note["title"]), data.get("body", note["body"]), id))
    db().commit()
    row = db().execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
    return jsonify(dict(row))


@app.get("/api/notes/<int:id>/export")
def export_note(id):
    login_required()
    note = db().execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
    if note is None:
        abort(404)
    return jsonify(dict(note))


@app.get("/api/v1/notes/<int:id>")
def get_note_v1(id):
    user = login_required()
    note = db().execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
    if note is None or note["owner_id"] != user["id"]:
        abort(404)
    return jsonify(dict(note))


@app.get("/api/v1/notes/<int:id>/export")
def export_note_v1(id):
    login_required()
    note = db().execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
    if note is None:
        abort(404)
    return jsonify(dict(note))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False, use_reloader=False)

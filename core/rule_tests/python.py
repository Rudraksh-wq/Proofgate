# Test cases for rules/python.yaml (semgrep --test convention: `# ruleid:` = must match the next line,
# `# ok:` = must not). Deliberately vulnerable code, never executed.
import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request, send_file

app = Flask(__name__)
ALLOWED = {"id": "id", "title": "title"}


def sql_cases(cur):
    q = request.args.get("q", "")
    # ruleid: proofgate.py-sql-injection
    cur.execute(f"SELECT * FROM notes WHERE title LIKE '%{q}%'")
    # ruleid: proofgate.py-sql-injection
    cur.execute("SELECT * FROM notes WHERE title = '" + q + "'")
    # ok: proofgate.py-sql-injection
    cur.execute("SELECT * FROM notes WHERE title LIKE ?", (f"%{q}%",))
    order = ALLOWED.get(request.args.get("sort", "id"), "id")
    # ok: proofgate.py-sql-injection
    cur.execute(f"SELECT * FROM notes ORDER BY {order}")
    # ok: proofgate.py-sql-injection
    cur.execute("SELECT 1")


def shell_cases(name):
    # ruleid: proofgate.py-shell-true
    subprocess.run(f"echo {name}", shell=True)
    # ok: proofgate.py-shell-true
    subprocess.run(["echo", name])


def os_system_cases(name):
    # ruleid: proofgate.py-os-system
    os.system("ls " + name)
    # ok: proofgate.py-os-system
    os.system("ls -la")


def debug_cases():
    # ruleid: proofgate.py-flask-debug-true
    app.run(host="127.0.0.1", debug=True)
    # ok: proofgate.py-flask-debug-true
    app.run(host="127.0.0.1", debug=False)


def tls_cases(url):
    # ruleid: proofgate.py-requests-verify-false
    requests.get(url, verify=False)
    # ok: proofgate.py-requests-verify-false
    requests.get(url, timeout=3)


def jwt_cases(jwt, token):
    # ruleid: proofgate.py-jwt-no-verify
    jwt.decode(token, verify=False)
    # ruleid: proofgate.py-jwt-no-verify
    jwt.decode(token, options={"verify_signature": False})
    # ok: proofgate.py-jwt-no-verify
    jwt.decode(token, "k", algorithms=["HS256"])


# ruleid: proofgate.py-flask-hardcoded-secret-key
app.secret_key = "a-literal-value"
# ok: proofgate.py-flask-hardcoded-secret-key
app.secret_key = os.environ["SECRET_KEY"]


def deser_cases(blob, text):
    # ruleid: proofgate.py-unsafe-deserialization
    pickle.loads(blob)
    # ruleid: proofgate.py-unsafe-deserialization
    yaml.load(text)
    # ok: proofgate.py-unsafe-deserialization
    yaml.safe_load(text)


def ssti_cases(user_text):
    # ruleid: proofgate.py-flask-ssti
    render_template_string(user_text)
    # ok: proofgate.py-flask-ssti
    render_template_string("<p>{{ name }}</p>", name=user_text)


def path_cases():
    name = request.args.get("file")
    # ruleid: proofgate.py-path-traversal
    send_file(name)
    # ruleid: proofgate.py-path-traversal
    open(name)
    # ok: proofgate.py-path-traversal
    send_file("static/logo.png")


def ssrf_cases():
    target = request.args.get("url")
    # ruleid: proofgate.py-ssrf
    requests.get(target)
    # ok: proofgate.py-ssrf
    requests.get("https://api.example.com/health")


def cors_cases(CORS):
    # ruleid: proofgate.py-cors-wildcard-credentials
    CORS(app, supports_credentials=True, origins="*")
    # ok: proofgate.py-cors-wildcard-credentials
    CORS(app, supports_credentials=True, origins="https://app.example.com")

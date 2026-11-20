import base64
import json
import re
import sys

from corpus_harness import CORPUS, FIXES, ROOT, running, start_many

sys.path.insert(0, str(ROOT / "demo-apps"))
import generate_corpus as gen  # noqa: E402

APP_NAMES = sorted(gen.app_specs())
FIX_NAMES = sorted(gen.FIX_SPECS)


def test_sixteen_apps_and_twelve_fixes():
    assert len(APP_NAMES) == 16 and len(FIX_NAMES) == 12
    for n in APP_NAMES:
        for f in ("app.py", "requirements.txt", "PROMPT.md"):
            assert (CORPUS / n / f).is_file(), (n, f)
    for n in FIX_NAMES:
        assert (FIXES / n / "app.py").is_file()


def test_committed_files_match_generator_output(tmp_path):
    gen.build(tmp_path / "corpus", tmp_path / "fixes")
    for committed, fresh in ((CORPUS, tmp_path / "corpus"), (FIXES, tmp_path / "fixes")):
        for f in fresh.rglob("*"):
            if f.is_file():
                other = committed / f.relative_to(fresh)
                assert other.is_file() and f.read_bytes() == other.read_bytes(), f"stale: {other}"


def test_prompt_is_the_same_for_every_app():
    prompts = {(CORPUS / n / "PROMPT.md").read_text(encoding="utf-8") for n in APP_NAMES}
    assert len(prompts) == 1


def test_every_app_reads_port_and_db_path():
    for n in APP_NAMES:
        src = (CORPUS / n / "app.py").read_text(encoding="utf-8")
        assert 'os.environ.get("PORT"' in src and 'os.environ.get("DB_PATH"' in src, n


def test_ground_truth_shape_and_locations():
    truth = json.loads((CORPUS / "ground_truth.json").read_text(encoding="utf-8"))
    assert sorted(truth) == APP_NAMES
    for name, items in truth.items():
        if name.startswith("c"):
            assert items == [], name
            continue
        assert items, name
        for it in items:
            assert set(it) == {"category", "cwe", "label", "file", "line"} and it["cwe"].startswith("CWE-")
            _, needle = gen.LOCATE[it["label"]]
            lines = (CORPUS / name / it["file"]).read_text(encoding="utf-8").splitlines()
            assert needle in lines[it["line"] - 1], (name, it)


def test_ground_truth_never_contains_a_key_value():
    raw = (CORPUS / "ground_truth.json").read_text(encoding="utf-8")
    assert not re.search(r"sk_(live|test)_|eyJ", raw)


def test_fixes_json_shape():
    fixes = json.loads((FIXES / "fixes.json").read_text(encoding="utf-8"))
    assert sorted(fixes) == FIX_NAMES
    for name, meta in fixes.items():
        assert set(meta) == {"app", "kind", "should_accept"}
        assert meta["should_accept"] == (meta["kind"] == "correct")
        assert meta["app"] in APP_NAMES
    assert {m["app"] for m in fixes.values()} == {"v01_idor_read", "v05_unauth_admin", "v06_mass_assign", "v07_sqli"}
    assert sum(m["should_accept"] for m in fixes.values()) == 4


def test_fake_package_confirmed_404_and_cached():
    cached = json.loads((CORPUS / "registry_check.json").read_text(encoding="utf-8"))
    assert cached["package"] == gen.FAKE_PACKAGE and cached["status"] == 404
    assert gen.FAKE_PACKAGE in (CORPUS / "v11_hallucinated_dep" / "requirements.txt").read_text(encoding="utf-8")


def test_all_28_apps_start_and_signup_works(tmp_path):
    dirs = [CORPUS / n for n in APP_NAMES] + [FIXES / n for n in FIX_NAMES]
    apps = start_many(dirs, tmp_path)
    try:
        for a in apps:
            r = a.call("POST", "/signup", json={"email": "x@example.test", "password": "pw"})
            assert r.status_code == 201 and "token" in r.json(), a.dir.name
    finally:
        for a in apps:
            a.stop()


# ----------------------------------------------------------------- planted flaws behave as labelled
def _two_users(app):
    a, b = app.signup("a@example.test"), app.signup("b@example.test")
    note = app.call("POST", "/notes", a["token"], json={"title": "t", "body": "PGCANARY_A_test"}).json()
    return a, b, note


def test_clean_app_isolates_users(tmp_path):
    with running(CORPUS / "c01_clean", tmp_path) as app:
        a, b, note = _two_users(app)
        assert app.call("GET", f"/notes/{note['id']}", a["token"]).status_code == 200  # owner oracle
        assert app.call("GET", f"/notes/{note['id']}", b["token"]).status_code == 404
        assert app.call("GET", f"/notes/{note['id']}").status_code == 401
        assert app.call("PUT", f"/notes/{note['id']}", b["token"], json={"title": "x"}).status_code == 404
        assert "PGCANARY" not in app.call("GET", f"/notes?user_id={a['id']}", b["token"]).text
        assert "PGCANARY" not in app.call("GET", "/search?q=x%25'%20OR%20'1'='1", b["token"]).text
        assert app.call("GET", "/admin/users").status_code == 401
        assert app.call("GET", "/admin/users", b["token"]).status_code == 403
        r = app.call("PUT", "/profile", b["token"], json={"display_name": "Bee", "role": "admin"})
        assert r.json()["display_name"] == "Bee" and r.json()["role"] == "user"


def test_c02_helper_and_c03_bait_are_clean(tmp_path):
    for name in ("c02_clean_helper", "c03_bait"):
        with running(CORPUS / name, tmp_path) as app:
            a, b, note = _two_users(app)
            assert app.call("GET", f"/notes/{note['id']}", a["token"]).status_code == 200
            assert app.call("GET", f"/notes/{note['id']}", b["token"]).status_code == 404
            assert app.call("GET", "/notes?sort=title", a["token"]).status_code == 200


def test_v01_idor_read(tmp_path):
    with running(CORPUS / "v01_idor_read", tmp_path) as app:
        a, b, note = _two_users(app)
        assert "PGCANARY_A_test" in app.call("GET", f"/notes/{note['id']}", b["token"]).text


def test_v02_idor_write(tmp_path):
    with running(CORPUS / "v02_idor_write", tmp_path) as app:
        a, b, note = _two_users(app)
        assert app.call("PUT", f"/notes/{note['id']}", b["token"], json={"title": "pwned"}).status_code == 200
        assert app.call("GET", f"/notes/{note['id']}", a["token"]).json()["title"] == "pwned"


def test_v03_list_param(tmp_path):
    with running(CORPUS / "v03_idor_param", tmp_path) as app:
        a, b, _ = _two_users(app)
        assert "PGCANARY_A_test" in app.call("GET", f"/notes?user_id={a['id']}", b["token"]).text


def test_v04_missing_role_and_v05_unauth_admin(tmp_path):
    with running(CORPUS / "v04_missing_role", tmp_path) as app:
        a, b, _ = _two_users(app)
        assert "a@example.test" in app.call("GET", "/admin/users", b["token"]).text
        assert app.call("GET", "/admin/users").status_code == 401
    with running(CORPUS / "v05_unauth_admin", tmp_path) as app:
        _two_users(app)
        assert "a@example.test" in app.call("GET", "/admin/users").text


def test_v06_mass_assignment(tmp_path):
    with running(CORPUS / "v06_mass_assign", tmp_path) as app:
        _, b, _ = _two_users(app)
        assert app.call("PUT", "/profile", b["token"], json={"role": "admin"}).json()["role"] == "admin"
        assert app.call("GET", "/admin/users", b["token"]).status_code == 200


def test_v07_sqli_leaks_other_users_notes(tmp_path):
    with running(CORPUS / "v07_sqli", tmp_path) as app:
        _, b, _ = _two_users(app)
        assert "PGCANARY" not in app.call("GET", "/search", b["token"], params={"q": "zzz"}).text
        payload = "zzz%' OR '1'='1' OR title LIKE '%"
        assert "PGCANARY_A_test" in app.call("GET", "/search", b["token"], params={"q": payload}).text


def test_v08_shell_injection_computes_not_just_echoes(tmp_path):
    payload = "& set /a 6*7" if sys.platform == "win32" else "$((6*7))"
    with running(CORPUS / "v08_cmdi", tmp_path) as app:
        _, b, _ = _two_users(app)
        out = app.call("GET", "/export", b["token"], params={"name": payload}).json()["result"]
        assert "42" in out  # the payload text itself contains no "42", so this was computed by a shell


def _jwt_role(token: str) -> str:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["role"]


def test_templates_have_placeholders_and_no_secret_shaped_text():
    for name, rels in gen.SECRET_FILES.items():
        for rel in rels:
            tmpl = (CORPUS / name / (rel + gen.TMPL)).read_text(encoding="utf-8")
            assert "{{FAKE_" in tmpl and not re.search(r"sk_(live|test)_[A-Za-z0-9]{8}|eyJ", tmpl), (name, rel)


def test_rendered_files_hold_real_format_fake_secrets_with_fresh_values():
    v09 = (CORPUS / "v09_hardcoded_keys" / "app.py").read_text(encoding="utf-8")
    assert re.search(r'STRIPE_SECRET_KEY = "sk_live_[0-9a-f]{24}"', v09)
    jwt = re.search(r'SUPABASE_SERVICE_ROLE_KEY = "([^"]+)"', v09).group(1)
    assert _jwt_role(jwt) == "service_role" and "{{" not in v09
    bundle = (CORPUS / "v10_service_role_in_bundle" / "static" / "bundle.js").read_text(encoding="utf-8")
    assert _jwt_role(re.search(r'SUPABASE_KEY = "([^"]+)"', bundle).group(1)) == "service_role"
    assert "sourceMappingURL" in bundle
    assert gen.fake_stripe() != gen.fake_stripe()


def test_other_planted_flaws_present():
    assert "requests==2.19.0" in (CORPUS / "v12_outdated_dep" / "requirements.txt").read_text(encoding="utf-8")
    v13 = (CORPUS / "v13_debug_tls" / "app.py").read_text(encoding="utf-8")
    assert "debug=True" in v13 and "verify=False" in v13


def test_c03_bait_has_anon_key_only():
    import base64

    src = (CORPUS / "c03_bait" / "app.py").read_text(encoding="utf-8")
    jwt = next(tok for tok in src.split('"') if tok.startswith("eyJ"))
    payload = jwt.split(".")[1]
    role = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["role"]
    assert role == "anon" and "service_role" not in src and "sk_live" not in src


# ----------------------------------------------------------------- candidate fixes
def _fix(kind_app):
    return FIXES / kind_app


def test_v01_fixes(tmp_path):
    for kind, other_reads_note, owner_ok in (("correct", False, True), ("lazy", False, False), ("partial", True, True)):
        with running(_fix(f"v01_{kind}"), tmp_path) as app:
            a, b, note = _two_users(app)
            leaked = "PGCANARY_A_test" in app.call("GET", f"/notes/{note['id']}", b["token"]).text
            assert leaked == other_reads_note, kind
            assert (app.call("GET", f"/notes/{note['id']}", a["token"]).status_code == 200) == owner_ok, kind


def test_v05_fixes(tmp_path):
    for kind, anon_leaks, admin_ok in (("correct", False, True), ("lazy", False, False), ("partial", True, True)):
        with running(_fix(f"v05_{kind}"), tmp_path) as app:
            _, b, _ = _two_users(app)
            anon = app.call("GET", "/admin/users")
            fake_header = app.call("GET", "/admin/users", "not-a-real-token")
            assert ("a@example.test" in fake_header.text) == anon_leaks, kind
            assert "a@example.test" not in anon.text
            if kind == "correct":
                assert app.call("GET", "/admin/users", b["token"]).status_code == 403
            assert admin_ok or app.call("GET", "/admin/users", b["token"]).status_code == 403


def test_v06_fixes(tmp_path):
    for kind in ("correct", "lazy", "partial"):
        with running(_fix(f"v06_{kind}"), tmp_path) as app:
            _, b, _ = _two_users(app)
            resp = app.call("PUT", "/profile", b["token"], json={"is_admin": 1})
            escalated_flag = app.call("GET", "/profile", b["token"]).json()["is_admin"]
            app.call("PUT", "/profile", b["token"], json={"role": "admin"})
            escalated_role = app.call("GET", "/profile", b["token"]).json()["role"] == "admin"
            if kind == "partial":
                assert not escalated_flag and escalated_role  # blocks is_admin, forgets role
            else:
                assert not escalated_flag and not escalated_role, kind
            editable = app.call("PUT", "/profile", b["token"], json={"display_name": "Bee"})
            assert (editable.status_code == 200 and editable.json()["display_name"] == "Bee") == (kind != "lazy")
            assert resp is not None


def test_v07_fixes(tmp_path):
    payload = "zzz%' OR '1'='1' OR title LIKE '%"
    for kind, leaks, owner_search in (("correct", False, True), ("lazy", False, False), ("partial", True, True)):
        with running(_fix(f"v07_{kind}"), tmp_path) as app:
            a, b, _ = _two_users(app)
            assert ("PGCANARY_A_test" in app.call("GET", "/search", b["token"], params={"q": payload}).text) == leaks, kind
            own = app.call("GET", "/search", a["token"], params={"q": "t"})
            assert (own.status_code == 200 and "PGCANARY_A_test" in own.text) == owner_search, kind

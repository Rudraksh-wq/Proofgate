import datetime as dt
import statistics
import time
from pathlib import Path

import pytest
import yaml

from proofgate import inline
from proofgate.inline import check_file, dependency_lines, js_findings, python_findings
from proofgate.layers.l2_sast import RULES_DIR
from proofgate.pkgcache import PackageCache
from proofgate.models import Finding

from conftest import fake_secrets
from corpus_harness import CORPUS

SQL_RULE = "proofgate.py-sql-injection"


def rules_of(findings):
    return sorted({f.rule for f in findings})


def app_result(name: str, rel: str = "app.py", **kw):
    p = CORPUS / name / rel
    return check_file(p, project_root=CORPUS / name, cache=kw.pop("cache", None) or PackageCache(Path("nope.json")), **kw)


# ----------------------------------------------------------------------------- the corpus (done-when)
@pytest.mark.parametrize(
    "app,rel,expected",
    [
        ("v07_sqli", "app.py", {SQL_RULE}),
        ("v08_cmdi", "app.py", {"proofgate.py-shell-true"}),
        ("v09_hardcoded_keys", "app.py", {"stripe-live-secret-key", "supabase-service-role-key"}),
        ("v10_service_role_in_bundle", "static/bundle.js", {"supabase-service-role-key"}),
        ("v13_debug_tls", "app.py", {"proofgate.py-flask-debug-true", "proofgate.py-requests-verify-false"}),
    ],
)
def test_flags_the_planted_flaws(app, rel, expected):
    assert set(rules_of(app_result(app, rel).findings)) == expected


@pytest.mark.parametrize("app", ["c01_clean", "c02_clean_helper", "c03_bait"])
def test_clean_apps_and_the_bait_have_no_findings(app):
    assert app_result(app).findings == []


@pytest.mark.parametrize("app", ["v01_idor_read", "v02_idor_write", "v03_idor_param", "v04_missing_role",
                                 "v05_unauth_admin", "v11_hallucinated_dep", "v12_outdated_dep"])
def test_access_control_flaws_are_not_inline_findings(app):
    assert app_result(app).findings == []  # inline is for cheap, certain checks; L8 proves access bugs


def test_only_critical_secrets_block():
    assert app_result("v09_hardcoded_keys").blocked
    assert app_result("v10_service_role_in_bundle", "static/bundle.js").blocked
    for app in ("v07_sqli", "v08_cmdi", "v13_debug_tls", "c03_bait"):
        assert not app_result(app).blocked, app


def test_v11_fake_package_blocks_only_from_the_cache(tmp_path):
    req = CORPUS / "v11_hallucinated_dep" / "requirements.txt"
    fake = req.read_text(encoding="utf-8").splitlines()[1].split("==")[0]
    cold = check_file(req, cache=PackageCache(tmp_path / "c.json"))
    assert cold.findings == [] and ("pypi", fake) in cold.needs_lookup  # miss -> background lookup, no network

    cache = PackageCache(tmp_path / "c.json")
    cache.put("pypi", fake, exists=False)
    cache.put("pypi", "Flask", exists=True, first_release="2010-04-06", weekly_downloads=10**7)
    hot = check_file(req, cache=cache)
    (f,) = hot.findings
    assert f.rule == "package-does-not-exist" and f.severity == "critical" and f.layer == 4 and hot.blocked
    assert f.location.line == 2 and fake in f.title
    assert hot.needs_lookup == []


def test_v12_old_requests_is_a_layer3_matter_not_inline(tmp_path):
    cache = PackageCache(tmp_path / "c.json")
    cache.put("pypi", "requests", exists=True, first_release="2011-02-13")
    cache.put("pypi", "flask", exists=True, first_release="2010-04-06")
    assert check_file(CORPUS / "v12_outdated_dep" / "requirements.txt", cache=cache).findings == []


# ----------------------------------------------------------------------------- latency (target: <= 200 ms median)
def test_median_latency_per_file_is_under_200ms_over_50_runs(tmp_path):
    cache = PackageCache(tmp_path / "c.json")
    cache.put("pypi", "flask", exists=True, first_release="2010-04-06")
    cache.put("pypi", "requests", exists=True, first_release="2011-02-13")
    files = [CORPUS / a / "app.py" for a in ("c01_clean", "c03_bait", "v07_sqli", "v08_cmdi", "v09_hardcoded_keys", "v13_debug_tls")]
    files += [CORPUS / "v10_service_role_in_bundle" / "static" / "bundle.js", CORPUS / "v12_outdated_dep" / "requirements.txt"]
    medians = {}
    for f in files:
        samples = []
        for _ in range(50):
            t = time.perf_counter()
            check_file(f, cache=cache)
            samples.append((time.perf_counter() - t) * 1000)
        medians[f.name + ":" + f.parent.name] = statistics.median(samples)
    worst = max(medians.values())
    print(f"inline median ms per file: {medians}")
    assert worst <= 200, medians


# ----------------------------------------------------------------------------- Python AST rules
@pytest.mark.parametrize(
    "rule,code",
    [
        (SQL_RULE, "def f(c, q):\n    c.execute(f\"SELECT * FROM t WHERE a = '{q}'\")\n"),
        (SQL_RULE, "def f(c, q):\n    c.execute(\"SELECT * FROM t WHERE a = '\" + q + \"'\")\n"),
        (SQL_RULE, "def f(c, q):\n    c.execute(\"SELECT * FROM t WHERE a = '%s'\" % q)\n"),
        (SQL_RULE, "def f(c, q):\n    c.execute(\"SELECT {}\".format(q))\n"),
        ("proofgate.py-shell-true", "import subprocess\nsubprocess.run('ls', shell=True)\n"),
        ("proofgate.py-shell-true", "import subprocess\nsubprocess.Popen(cmd, shell=True)\n"),
        ("proofgate.py-os-system", "import os\nos.system('ls ' + name)\n"),
        ("proofgate.py-flask-debug-true", "app.run(debug=True)\n"),
        ("proofgate.py-requests-verify-false", "import requests\nrequests.get(u, verify=False)\n"),
        ("proofgate.py-requests-verify-false", "import ssl\nctx = ssl._create_unverified_context()\n"),
        ("proofgate.py-jwt-no-verify", "import jwt\njwt.decode(t, verify=False)\n"),
        ("proofgate.py-jwt-no-verify", "import jwt\njwt.decode(t, options={'verify_signature': False})\n"),
        ("proofgate.py-unsafe-deserialization", "import pickle\npickle.loads(b)\n"),
        ("proofgate.py-unsafe-deserialization", "import yaml\nyaml.load(s)\n"),
    ],
)
def test_python_rules_fire(rule, code):
    assert rule in rules_of(python_findings(code, "a.py"))


@pytest.mark.parametrize(
    "code",
    [
        "def f(c, q):\n    c.execute('SELECT * FROM t WHERE a = ?', (q,))\n",
        "def f(c):\n    c.execute('SELECT 1')\n",
        "ORDER = {'id': 'id'}\ndef f(c, s):\n    o = ORDER.get(s, 'id')\n    c.execute(f'SELECT * FROM t ORDER BY {o}')\n",
        "def f(c, n):\n    c.execute(f'SELECT * FROM t LIMIT {int(n)}')\n",
        "import subprocess\nsubprocess.run(['ls'])\n",
        "import os\nos.system('ls -la')\n",
        "app.run(debug=False)\n",
        "import requests\nrequests.get(u, timeout=3)\n",
        "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\nyaml.safe_load(s)\n",
        "import jwt\njwt.decode(t, key, algorithms=['HS256'])\n",
    ],
)
def test_python_safe_code_is_clean(code):
    assert python_findings(code, "a.py") == []


def test_allow_list_does_not_leak_between_functions():
    code = ("ORDER = {}\n"
            "def a(s):\n    o = ORDER.get(s, 'id')\n    return o\n"
            "def b(c, o):\n    c.execute(f'SELECT * FROM t ORDER BY {o}')\n")
    assert SQL_RULE in rules_of(python_findings(code, "a.py"))


def test_unparseable_fragment_is_not_a_crash():
    assert python_findings("def (:\n  x = ", "a.py") == []
    assert check_file("frag.py", "def (:\n  x = ").findings == []


# ----------------------------------------------------------------------------- JS / TS rules
@pytest.mark.parametrize(
    "rule,code",
    [
        ("proofgate.js-eval", "eval(userInput);"),
        ("proofgate.js-eval", "const f = new Function('a', body);"),
        ("proofgate.js-dangerously-set-inner-html", "<div dangerouslySetInnerHTML={{ __html: html }} />"),
        ("proofgate.js-innerhtml-assignment", "el.innerHTML = userHtml;"),
        ("proofgate.js-child-process-exec", "cp.exec(`ls ${dir}`);"),
        ("proofgate.js-child-process-exec", "execSync('ls ' + dir);"),
        ("proofgate.js-supabase-rpc-string-sql", "await sb.rpc('run_sql', { query: `select ${x}` });"),
        ("proofgate.js-public-env-secret", "const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;"),
    ],
)
def test_js_rules_fire(rule, code):
    assert rule in rules_of(js_findings(code, "a.ts"))


@pytest.mark.parametrize(
    "code",
    [
        "eval('1 + 1');",
        "<div dangerouslySetInnerHTML={{ __html: '<b>x</b>' }} />",
        "el.innerHTML = '<b>x</b>';",
        "cp.execFile('ls', [dir]);",
        "await sb.rpc('get_note', { note_id: id });",
        "const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;",
        "// eval(userInput) is bad",
        " * el.innerHTML = x",
    ],
)
def test_js_safe_code_is_clean(code):
    assert js_findings(code, "a.ts") == []


def test_service_role_only_matters_in_route_handlers():
    code = "const c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\n"
    assert "proofgate.next-route-service-role-client" in rules_of(js_findings(code, "app/api/notes/route.ts"))
    assert js_findings(code, "scripts/seed.ts") == []


# ----------------------------------------------------------------------------- dependency parsing + cache
def test_requirements_parsing():
    src = "# c\nFlask>=3.0\nrequests[security]==2.19.0 ; python_version>'3'\n-r other.txt\ngit+https://x/y.git\n\nPyYAML\n"
    assert dependency_lines(src, "requirements.txt") == [("pypi", "Flask", 2), ("pypi", "requests", 3), ("pypi", "PyYAML", 7)]


def test_package_json_parsing_skips_non_registry_specs():
    src = ('{\n  "name": "app",\n  "dependencies": {\n    "next": "14.0.0",\n    "@supabase/ssr": "^0.5.0",\n'
           '    "local": "file:../local",\n    "gh": "github:a/b"\n  }\n}\n')
    assert dependency_lines(src, "package.json") == [("npm", "next", 4), ("npm", "@supabase/ssr", 5)]


def test_new_package_is_a_warning_not_a_block(tmp_path):
    cache = PackageCache(tmp_path / "c.json")
    now = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
    cache.put("npm", "shiny-new-lib", exists=True, first_release="2026-11-10")
    res = check_file("package.json", '{\n  "dependencies": {\n    "shiny-new-lib": "1.0.0"\n  }\n}\n', cache=cache, now=now)
    (f,) = res.findings
    assert f.rule == "package-very-new" and f.severity == "high" and not res.blocked


def test_stale_cache_entry_counts_as_a_miss(tmp_path):
    cache = PackageCache(tmp_path / "c.json", ttl=dt.timedelta(seconds=-1))
    cache.put("pypi", "flask", exists=True)
    assert cache.get("pypi", "flask") is None and cache.get("pypi", "flask", allow_stale=True)


def test_cache_roundtrip_and_name_normalisation(tmp_path):
    c = PackageCache(tmp_path / "c.json")
    c.put("pypi", "My_Package.Name", exists=True)
    c.save()
    again = PackageCache(tmp_path / "c.json")
    assert again.get("pypi", "my-package-name")["exists"] is True


def test_corrupt_cache_file_is_ignored(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("{nope", encoding="utf-8")
    assert PackageCache(p).get("pypi", "flask") is None


# ----------------------------------------------------------------------------- robustness + consistency
def test_inline_findings_carry_no_secret(no_leaks):
    raw = [t for t in (CORPUS / "v09_hardcoded_keys" / "app.py").read_text(encoding="utf-8").replace('"', " ").split()
           if t.startswith(("sk_", "eyJ"))]
    assert raw
    for f in app_result("v09_hardcoded_keys").findings:
        Finding.model_validate(f.to_json_dict())
        no_leaks(f.to_json(), secrets=raw)


def test_secret_in_an_edit_is_blocked_with_a_built_at_runtime_key():
    res = check_file("app.py", f'KEY = "{fake_secrets()["stripe"]}"\n')
    assert res.blocked and res.blockers[0].plain_words.lower().count("rotate")


def test_never_raises_on_odd_input(tmp_path):
    assert check_file(tmp_path / "missing.py").findings == []
    assert check_file("x.bin", "\x00\x01\x02" * 100).findings == []
    assert check_file("x.py", "").findings == []
    assert check_file("README.md", "just text").findings == []


def test_rule_table_matches_the_semgrep_rules():
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    yaml_rules = {}
    for f in RULES_DIR.glob("*.yaml"):
        for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]:
            yaml_rules[r["id"]] = r
    for rid, (cwe, category, severity, _conf, _title, _plain, _tier) in inline.RULE_TABLE.items():
        r = yaml_rules[rid]
        assert r["metadata"]["cwe"][0].startswith(cwe + ":"), rid
        assert r["metadata"]["category"] == category, rid
        assert sev[r["severity"]] == severity, rid

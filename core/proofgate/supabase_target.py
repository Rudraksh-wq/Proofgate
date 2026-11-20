"""Where ProofGate's Supabase checks run, and the guard that stops them touching anything that is not yours (plan 3.2, 8).

Two backends, no Docker requirement anywhere:

  hosted  your own Supabase test project, reached with the keys in the git-ignored `.env` (the default on a machine without Docker).
  local   `supabase start` on localhost. Used only if Docker and the Supabase CLI happen to exist (for example on a CI runner).
  auto    hosted when a non-local SUPABASE_URL is configured, else local when it is available, else "not configured" (a recorded skip).

Select with `--backend hosted|local|auto` or PROOFGATE_SUPABASE_BACKEND (the flag wins).

HOSTED GUARD. A hosted target is used only when ALL of these hold:
  * its project ref (the `xxxx` of `https://xxxx.supabase.co`) is listed in PROOFGATE_ALLOWED_PROJECT_REFS (comma separated, exact match);
  * the caller passed `--i-own-this` (or set PROOFGATE_I_OWN_THIS=1, meant for tests);
  * the database URL, if given, points at the same project (or at localhost).
Every hosted run is logged in the report. localhost needs neither. Key values are never printed: `repr()` masks them.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlparse

from .probe.guard import TargetRefused, _is_local_host

BACKENDS = ("hosted", "local", "auto")
ENV_NAMES = ("SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_DB_URL", "PROOFGATE_ALLOWED_PROJECT_REFS",
             "PROOFGATE_SUPABASE_BACKEND")
_REF_OK = re.compile(r"^[a-z0-9]{3,40}$")
_HOSTED_HOST = re.compile(r"^([a-z0-9]+)\.supabase\.(?:co|red)$")
_DB_DIRECT = re.compile(r"^db\.([a-z0-9]+)\.supabase\.(?:co|red)$")
_DB_USER_REF = re.compile(r"^[a-z_]+\.([a-z0-9]+)$")  # pooler users look like postgres.<ref>


class SupabaseTargetRefused(TargetRefused):
    """The Supabase target is not allowed: not allow-listed, no ownership flag, or not a Supabase project we can identify."""


class BackendUnavailable(Exception):
    """The backend cannot run here (not configured, no Docker, no psycopg...). Callers record a skip; it is never a crash."""


# ------------------------------------------------------------------------------------------- .env + config
def read_env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE lines of a .env file. Values are returned to the caller and never logged."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().removeprefix("export ").strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        elif " #" in v:
            v = v.split(" #", 1)[0].rstrip()
        out[k] = v
    return out


def _mask(value: str | None) -> str:
    return "<set>" if value else "<empty>"


@dataclass
class SupabaseConfig:
    url: str = ""
    anon_key: str = field(default="", repr=False)
    service_role_key: str = field(default="", repr=False)
    db_url: str = field(default="", repr=False)
    allowed_refs: tuple[str, ...] = ()
    backend: str = "auto"
    i_own_this_env: bool = False

    def __repr__(self) -> str:  # names and whether they are set, never values
        return (f"SupabaseConfig(url={self.url!r}, anon_key={_mask(self.anon_key)}, service_role_key={_mask(self.service_role_key)}, "
                f"db_url={_mask(self.db_url)}, allowed_refs={self.allowed_refs!r}, backend={self.backend!r})")

    @property
    def configured(self) -> bool:
        return bool(self.url)


def parse_refs(text: str | None) -> tuple[str, ...]:
    refs = []
    for part in (text or "").split(","):
        p = part.strip().lower()
        if not p:
            continue
        if not _REF_OK.match(p):
            raise SupabaseTargetRefused(f"PROOFGATE_ALLOWED_PROJECT_REFS: {part.strip()!r} is not a project ref (lowercase letters and digits; no wildcards)")
        refs.append(p)
    return tuple(refs)


def load_config(project: str | Path | None = None, environ: dict[str, str] | None = None, *, env_file: Path | None = None) -> SupabaseConfig:
    """Process environment first, then the project's git-ignored `.env`. Nothing is exported or logged."""
    env = dict(os.environ if environ is None else environ)
    file_vals: dict[str, str] = {}
    if env_file is None and project is not None:
        env_file = Path(project) / ".env"
    if env_file is not None:
        file_vals = read_env_file(env_file)
    get = lambda k: (env.get(k) or file_vals.get(k) or "").strip()  # noqa: E731
    backend = (get("PROOFGATE_SUPABASE_BACKEND") or "auto").lower()
    if backend not in BACKENDS:
        raise SupabaseTargetRefused(f"PROOFGATE_SUPABASE_BACKEND must be one of {', '.join(BACKENDS)}, got {backend!r}")
    return SupabaseConfig(
        url=get("SUPABASE_URL").rstrip("/"), anon_key=get("SUPABASE_ANON_KEY"), service_role_key=get("SUPABASE_SERVICE_ROLE_KEY"),
        db_url=get("SUPABASE_DB_URL"), allowed_refs=parse_refs(get("PROOFGATE_ALLOWED_PROJECT_REFS")), backend=backend,
        i_own_this_env=get("PROOFGATE_I_OWN_THIS") == "1")


# ------------------------------------------------------------------------------------------- the guard
def project_ref(url: str) -> str | None:
    """The project ref of a hosted Supabase API URL, else None."""
    host = (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower()
    m = _HOSTED_HOST.match(host)
    return m.group(1) if m else None


def db_url_ref(db_url: str) -> str | None:
    p = urlparse(db_url)
    host = (p.hostname or "").lower()
    m = _DB_DIRECT.match(host)
    if m:
        return m.group(1)
    m = _DB_USER_REF.match(unquote(p.username or ""))
    return m.group(1) if m else None


@dataclass(frozen=True)
class GuardDecision:
    local: bool
    ref: str | None
    host: str
    override_note: str | None  # shown in every report of a hosted run


def guard_supabase(url: str, *, db_url: str = "", allowed_refs: tuple[str, ...] = (), i_own_this: bool = False,
                   i_own_this_env: bool = False) -> GuardDecision:
    """Raise SupabaseTargetRefused unless the target is localhost, or an allow-listed hosted project the caller says they own."""
    if not url:
        raise SupabaseTargetRefused("no SUPABASE_URL: nothing to test")
    host = (urlparse(url if "://" in url else f"http://{url}").hostname or "").lower()
    if not host:
        raise SupabaseTargetRefused(f"not a valid Supabase URL: {url!r}")
    if _is_local_host(host):
        db_host = (urlparse(db_url).hostname or "") if db_url else ""
        if db_url and not _is_local_host(db_host):
            raise SupabaseTargetRefused("SUPABASE_URL is local but SUPABASE_DB_URL is not: refusing to mix a local API with a remote database")
        return GuardDecision(True, None, host, None)
    ref = project_ref(url)
    if ref is None:
        raise SupabaseTargetRefused(f"refusing {host!r}: it is not localhost and not a <ref>.supabase.co project, so ProofGate cannot tell whose it is")
    if ref not in allowed_refs:
        listed = ", ".join(allowed_refs) if allowed_refs else "(empty)"
        raise SupabaseTargetRefused(
            f"refusing project ref {ref!r}: it is not in PROOFGATE_ALLOWED_PROJECT_REFS ({listed}). Add the ref of YOUR OWN test project "
            "to PROOFGATE_ALLOWED_PROJECT_REFS in .env if you really mean to test it.")
    if not (i_own_this or i_own_this_env):
        raise SupabaseTargetRefused(f"refusing project ref {ref!r}: pass --i-own-this to confirm this is your own test project (the override is logged in the report)")
    if db_url:
        db_host = (urlparse(db_url).hostname or "").lower()
        dref = db_url_ref(db_url)
        if not _is_local_host(db_host) and dref != ref:
            raise SupabaseTargetRefused(f"SUPABASE_DB_URL points at project {dref or db_host!r}, not {ref!r}: refusing to run against a different database")
    return GuardDecision(False, ref, host, f"hosted Supabase project {ref}: test traffic was sent to it (--i-own-this)")


# ------------------------------------------------------------------------------------------- backends
def docker_available(timeout: float = 5.0) -> bool:
    """True only if a docker daemon answers within `timeout` seconds. Never raises, never hangs."""
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        return subprocess.run([exe, "info"], capture_output=True, timeout=timeout).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def local_available() -> tuple[bool, str]:
    if shutil.which("supabase") is None:
        return False, "the Supabase CLI is not installed"
    if not docker_available():
        return False, "Docker is not running or not installed"
    return True, "supabase CLI and Docker found"


@dataclass(frozen=True)
class SupabaseTarget:
    backend: str  # hosted | local
    url: str
    anon_key: str = field(repr=False)
    service_role_key: str = field(repr=False)
    db_url: str = field(repr=False)
    ref: str | None
    override_note: str | None

    def __repr__(self) -> str:
        return f"SupabaseTarget(backend={self.backend!r}, url={self.url!r}, ref={self.ref!r}, db_url={_mask(self.db_url)})"

    def connect(self):
        """A psycopg connection to SUPABASE_DB_URL. Raises BackendUnavailable (never anything stranger) when it cannot."""
        if not self.db_url:
            raise BackendUnavailable("SUPABASE_DB_URL is not set")
        try:
            import psycopg
        except ImportError:
            raise BackendUnavailable("the psycopg package is not installed (pip install 'proofgate[supabase]')") from None
        try:
            return psycopg.connect(self.db_url, connect_timeout=10)
        except Exception as e:  # noqa: BLE001 - the message can contain the URL: mask it
            raise BackendUnavailable(f"could not connect to the database: {type(e).__name__}") from None


def resolve_target(config: SupabaseConfig, *, backend: str | None = None, i_own_this: bool = False,
                   local_ok: tuple[bool, str] | None = None) -> SupabaseTarget:
    """Pick the backend and run the guard. Raises BackendUnavailable (a skip) when nothing is configured, SupabaseTargetRefused when forbidden."""
    want = (backend or config.backend or "auto").lower()
    if want not in BACKENDS:
        raise SupabaseTargetRefused(f"--backend must be one of {', '.join(BACKENDS)}")
    hosted_url = config.url and not _is_local_host((urlparse(config.url if "://" in config.url else f"http://{config.url}").hostname or ""))
    if want == "auto":
        if hosted_url:
            want = "hosted"
        elif config.url or (local_ok or local_available())[0]:
            want = "local"
        else:
            raise BackendUnavailable("no Supabase backend: not configured (set SUPABASE_URL in .env; or run `supabase start` where Docker exists)")
    if want == "hosted":
        if not config.url:
            raise BackendUnavailable("hosted backend: not configured (SUPABASE_URL is empty)")
        if not hosted_url:
            raise SupabaseTargetRefused("--backend hosted was requested but SUPABASE_URL points at localhost")
        d = guard_supabase(config.url, db_url=config.db_url, allowed_refs=config.allowed_refs, i_own_this=i_own_this, i_own_this_env=config.i_own_this_env)
        return SupabaseTarget("hosted", config.url, config.anon_key, config.service_role_key, config.db_url, d.ref, d.override_note)
    ok, why = local_ok or local_available()
    if not config.url and not ok:
        raise BackendUnavailable(f"local backend: unavailable ({why})")
    url = config.url or "http://127.0.0.1:54321"
    d = guard_supabase(url, db_url=config.db_url)
    if not d.local:
        raise SupabaseTargetRefused("--backend local was requested but SUPABASE_URL is not localhost")
    return SupabaseTarget("local", url, config.anon_key, config.service_role_key,
                          config.db_url or "postgresql://postgres:postgres@127.0.0.1:54322/postgres", None, None)


def backend_status(config: SupabaseConfig, *, local_ok: tuple[bool, str] | None = None) -> list[tuple[str, str, str]]:
    """Rows for `proofgate doctor`: (backend, status, detail). Never raises, never prints a key."""
    rows: list[tuple[str, str, str]] = []
    hosted_url = config.url and not _is_local_host(urlparse(config.url if "://" in config.url else f"http://{config.url}").hostname or "")
    if not hosted_url:
        rows.append(("hosted", "not configured", "set SUPABASE_URL (your own test project) in .env"))
    else:
        ref = project_ref(config.url)
        problems = []
        if ref is None:
            problems.append("SUPABASE_URL is not a <ref>.supabase.co URL")
        elif ref not in config.allowed_refs:
            problems.append(f"ref {ref} is not in PROOFGATE_ALLOWED_PROJECT_REFS")
        for name, val in (("SUPABASE_ANON_KEY", config.anon_key), ("SUPABASE_SERVICE_ROLE_KEY", config.service_role_key), ("SUPABASE_DB_URL", config.db_url)):
            if not val:
                problems.append(f"{name} is empty")
        rows.append(("hosted", "blocked" if problems else "configured", "; ".join(problems) if problems else f"project {ref}; needs --i-own-this to run"))
    ok, why = local_ok or local_available()
    rows.append(("local", "available" if ok else "unavailable", why + ("" if ok else " (optional: used only where Docker exists, such as CI)")))
    try:
        import psycopg  # noqa: F401

        rows.append(("psycopg", "ok", "database driver for hosted migrations and Splinter"))
    except ImportError:
        rows.append(("psycopg", "missing", "pip install 'proofgate[supabase]' to run migrations and Splinter"))
    rows.append(("backend", "setting", config.backend))
    return rows

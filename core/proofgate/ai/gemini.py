"""Gemini client (plan 3.1, 8): structured JSON out, validated with Pydantic, with backoff, an on-disk cache and an
offline switch. Every payload goes through the redactor before it leaves the machine or touches the cache.

Rules this module enforces:
* the model name comes from GEMINI_MODEL and the key from GEMINI_API_KEY (env only; never logged, never cached);
* PROOFGATE_OFFLINE=1 means no call is ever made (cached answers may still be used);
* prompts are redacted first; the cache stores the REDACTED prompt and the validated answer, never a raw secret;
* an answer that does not validate against the schema is discarded, never trusted.

`GeminiUnavailable` is the one exception callers handle: it means "use the deterministic fallback".
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import Awaitable, Callable, TypeVar

from pydantic import BaseModel, ValidationError

from ..redact import redact

T = TypeVar("T", bound=BaseModel)
Transport = Callable[[str, str, type[BaseModel], float], Awaitable[str]]  # (model, prompt, schema, temperature) -> JSON text
Sleeper = Callable[[float], Awaitable[None]]

RETRYABLE_CODES = {408, 429, 500, 502, 503, 504}
MAX_PROMPT_CHARS = 24_000


class GeminiUnavailable(Exception):
    """No answer: offline, no key/model, quota exhausted, bad output. The caller must fall back."""


def is_offline() -> bool:
    return os.environ.get("PROOFGATE_OFFLINE") == "1"


def default_cache_dir() -> Path:
    base = os.environ.get("PROOFGATE_CACHE_DIR")
    return (Path(base) if base else Path.home() / ".cache" / "proofgate") / "gemini"


async def _sdk_transport(model: str, prompt: str, schema: type[BaseModel], temperature: float) -> str:
    """The only function that talks to Gemini. Imported lazily so the package works without google-genai."""
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    resp = await client.aio.models.generate_content(
        model=model, contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json", response_schema=schema,
                                           temperature=temperature))
    return resp.text or ""


def _error_code(exc: BaseException) -> int | None:
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    return code if isinstance(code, int) else None


class GeminiClient:
    def __init__(self, *, transport: Transport | None = None, cache_dir: Path | None = None, sleeper: Sleeper | None = None,
                 max_attempts: int = 4, base_delay: float = 1.0, timeout: float = 60.0):
        self._transport = transport or _sdk_transport
        self._real = transport is None
        self.cache_dir = Path(cache_dir) if cache_dir else default_cache_dir()
        self._sleep = sleeper or asyncio.sleep
        self.max_attempts, self.base_delay, self.timeout = max_attempts, base_delay, timeout
        self.calls = 0  # network calls actually made (tests and the report use this)

    # ------------------------------------------------------------------ availability
    @property
    def model(self) -> str | None:
        return os.environ.get("GEMINI_MODEL") or None

    def available(self) -> tuple[bool, str]:
        if is_offline():
            return False, "PROOFGATE_OFFLINE=1"
        if not self.model:
            return False, "GEMINI_MODEL is not set"
        if self._real and not os.environ.get("GEMINI_API_KEY"):
            return False, "GEMINI_API_KEY is not set"
        return True, ""

    # ------------------------------------------------------------------ cache
    def _cache_path(self, model: str, prompt: str, schema: type[BaseModel], temperature: float) -> Path:
        key = hashlib.sha256(f"{model}\0{schema.__name__}\0{temperature}\0{prompt}".encode()).hexdigest()
        return self.cache_dir / f"{key}.json"

    def _cache_get(self, path: Path, schema: type[T]) -> T | None:
        try:
            return schema.model_validate(json.loads(path.read_text(encoding="utf-8"))["answer"])
        except (OSError, ValueError, KeyError, ValidationError):
            return None

    def _cache_put(self, path: Path, prompt: str, answer: BaseModel, model: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            body = {"model": model, "prompt_redacted": prompt, "answer": json.loads(redact(answer.model_dump_json()))}
            path.write_text(json.dumps(body, indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
        except OSError:
            pass  # a cache that cannot be written is not an error

    # ------------------------------------------------------------------ the call
    async def generate(self, prompt: str, schema: type[T], *, temperature: float = 0.2) -> T:
        """Redact, check the cache, call with backoff, validate. Raises GeminiUnavailable if there is no usable answer."""
        safe = redact(prompt)[:MAX_PROMPT_CHARS]
        model = self.model or "unset"
        path = self._cache_path(model, safe, schema, temperature)
        hit = self._cache_get(path, schema)
        if hit is not None:
            return hit  # cached answers work offline and cost nothing
        ok, why = self.available()
        if not ok:
            raise GeminiUnavailable(why)

        last = ""
        for attempt in range(self.max_attempts):
            try:
                self.calls += 1
                text = await asyncio.wait_for(self._transport(model, safe, schema, temperature), self.timeout)
                answer = schema.model_validate_json(text)
                self._cache_put(path, safe, answer, model)
                return answer
            except ValidationError as e:  # the model ignored the schema: retry once, then give up
                last = f"answer did not match the schema ({e.error_count()} errors)"
                if attempt >= 1:
                    break
            except asyncio.TimeoutError:
                last = "timed out"
            except Exception as e:  # noqa: BLE001 - SDK errors vary; classify by HTTP code
                code = _error_code(e)
                last = redact(f"{type(e).__name__}{f' {code}' if code else ''}")
                if code is not None and code not in RETRYABLE_CODES:
                    break  # bad key, bad request, blocked content: retrying cannot help
            if attempt < self.max_attempts - 1:
                await self._sleep(self.base_delay * (2 ** attempt))
        raise GeminiUnavailable(last or "no answer")

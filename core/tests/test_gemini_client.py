import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from proofgate.ai.gemini import MAX_PROMPT_CHARS, GeminiClient, GeminiUnavailable

from conftest import fake_secrets


class Answer(BaseModel):
    verdict: str
    score: int


GOOD = json.dumps({"verdict": "ok", "score": 3})


class ApiError(Exception):
    def __init__(self, code: int):
        super().__init__(f"api error {code}")
        self.code = code


class Fake:
    """A transport that plays back a script of answers/exceptions and records what it was sent."""

    def __init__(self, *script):
        self.script, self.sent = list(script), []

    async def __call__(self, model, prompt, schema, temperature):
        self.sent.append((model, prompt, schema.__name__, temperature))
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class Sleeps:
    def __init__(self):
        self.delays = []

    async def __call__(self, d):
        self.delays.append(d)


@pytest.fixture(autouse=True)
def online(monkeypatch):
    monkeypatch.setenv("PROOFGATE_OFFLINE", "0")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")
    monkeypatch.setenv("GEMINI_API_KEY", "not-a-real-key-for-tests")


def client(tmp_path, fake, **kw):
    sl = Sleeps()
    return GeminiClient(transport=fake, cache_dir=tmp_path / "cache", sleeper=sl, **kw), sl


# ----------------------------------------------------------------------------- availability
async def test_offline_makes_no_call(tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFGATE_OFFLINE", "1")
    fake = Fake(GOOD)
    c, _ = client(tmp_path, fake)
    with pytest.raises(GeminiUnavailable, match="PROOFGATE_OFFLINE=1"):
        await c.generate("hi", Answer)
    assert fake.sent == [] and c.calls == 0


async def test_model_must_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_MODEL")
    c, _ = client(tmp_path, Fake(GOOD))
    with pytest.raises(GeminiUnavailable, match="GEMINI_MODEL"):
        await c.generate("hi", Answer)


async def test_the_real_transport_needs_a_key(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY")
    c = GeminiClient(cache_dir=tmp_path / "c")  # no injected transport = the real SDK path
    with pytest.raises(GeminiUnavailable, match="GEMINI_API_KEY"):
        await c.generate("hi", Answer)


async def test_model_name_is_passed_through(tmp_path):
    fake = Fake(GOOD)
    c, _ = client(tmp_path, fake)
    assert (await c.generate("hi", Answer)) == Answer(verdict="ok", score=3)
    assert fake.sent[0][0] == "test-model" and fake.sent[0][2] == "Answer"


# ----------------------------------------------------------------------------- cache
async def test_second_identical_call_is_served_from_disk_even_offline(tmp_path, monkeypatch):
    fake = Fake(GOOD)
    c, _ = client(tmp_path, fake)
    await c.generate("same prompt", Answer)
    monkeypatch.setenv("PROOFGATE_OFFLINE", "1")
    again = await c.generate("same prompt", Answer)
    assert again.score == 3 and len(fake.sent) == 1


async def test_different_prompt_model_or_schema_is_a_different_cache_entry(tmp_path, monkeypatch):
    fake = Fake(GOOD, GOOD, GOOD)
    c, _ = client(tmp_path, fake)
    await c.generate("a", Answer)
    await c.generate("b", Answer)
    monkeypatch.setenv("GEMINI_MODEL", "other-model")
    await c.generate("a", Answer)
    assert len(fake.sent) == 3


async def test_corrupt_cache_entry_is_ignored(tmp_path):
    fake = Fake(GOOD, GOOD)
    c, _ = client(tmp_path, fake)
    await c.generate("x", Answer)
    for f in (tmp_path / "cache").glob("*.json"):
        f.write_text("{garbage", encoding="utf-8")
    assert (await c.generate("x", Answer)).verdict == "ok" and len(fake.sent) == 2


# ----------------------------------------------------------------------------- redaction on every payload
async def test_prompt_is_redacted_before_it_is_sent_and_before_it_is_cached(tmp_path, no_leaks):
    from proofgate.redact import new_canary

    secret, canary = fake_secrets()["stripe"], new_canary("A")
    fake = Fake(GOOD)
    c, _ = client(tmp_path, fake)
    await c.generate(f"key {secret} and row {canary}", Answer)
    _, sent, _, _ = fake.sent[0]
    no_leaks(sent, secrets=[secret], canaries=[canary])
    for f in (tmp_path / "cache").glob("*.json"):
        no_leaks(f.read_text(encoding="utf-8"), secrets=[secret, "not-a-real-key-for-tests"], canaries=[canary])


async def test_secret_in_the_answer_is_redacted_in_the_cache(tmp_path, no_leaks):
    secret = fake_secrets()["github"]
    fake = Fake(json.dumps({"verdict": f"token {secret}", "score": 1}))
    c, _ = client(tmp_path, fake)
    await c.generate("q", Answer)
    for f in (tmp_path / "cache").glob("*.json"):
        no_leaks(f.read_text(encoding="utf-8"), secrets=[secret])


async def test_the_api_key_never_reaches_the_cache_or_the_prompt(tmp_path):
    fake = Fake(GOOD)
    c, _ = client(tmp_path, fake)
    await c.generate("hello", Answer)
    blob = " ".join(f.read_text(encoding="utf-8") for f in (tmp_path / "cache").glob("*.json")) + fake.sent[0][1]
    assert "not-a-real-key-for-tests" not in blob


async def test_very_long_prompts_are_truncated(tmp_path):
    fake = Fake(GOOD)
    c, _ = client(tmp_path, fake)
    await c.generate("x" * (MAX_PROMPT_CHARS * 2), Answer)
    assert len(fake.sent[0][1]) == MAX_PROMPT_CHARS


# ----------------------------------------------------------------------------- backoff and failure
async def test_retries_rate_limits_with_exponential_backoff(tmp_path):
    fake = Fake(ApiError(429), ApiError(503), GOOD)
    c, sl = client(tmp_path, fake, base_delay=1.0)
    assert (await c.generate("q", Answer)).score == 3
    assert c.calls == 3 and sl.delays == [1.0, 2.0]


async def test_client_errors_are_not_retried(tmp_path):
    for code in (400, 401, 403):
        fake = Fake(ApiError(code), GOOD)
        c, sl = client(tmp_path / str(code), fake)
        with pytest.raises(GeminiUnavailable):
            await c.generate("q", Answer)
        assert c.calls == 1 and sl.delays == []


async def test_gives_up_after_max_attempts(tmp_path):
    fake = Fake(*[ApiError(500)] * 4)
    c, sl = client(tmp_path, fake, max_attempts=3)
    with pytest.raises(GeminiUnavailable):
        await c.generate("q", Answer)
    assert c.calls == 3 and len(sl.delays) == 2


async def test_timeout_is_retried_then_reported(tmp_path):
    import asyncio

    async def slow(*a):
        await asyncio.sleep(1)

    c = GeminiClient(transport=slow, cache_dir=tmp_path / "c", sleeper=Sleeps(), max_attempts=2, timeout=0.01)
    with pytest.raises(GeminiUnavailable, match="timed out"):
        await c.generate("q", Answer)
    assert c.calls == 2


async def test_answer_that_breaks_the_schema_gets_one_retry_then_is_discarded(tmp_path):
    bad = json.dumps({"verdict": 5})
    fake = Fake(bad, GOOD)
    c, _ = client(tmp_path, fake)
    assert (await c.generate("q", Answer)).score == 3 and c.calls == 2
    fake2 = Fake(bad, "not json at all", GOOD)
    c2, _ = client(tmp_path / "2", fake2)
    with pytest.raises(GeminiUnavailable, match="schema"):
        await c2.generate("q", Answer)
    assert c2.calls == 2  # never trusts an answer that does not validate


async def test_error_text_in_the_exception_is_redacted(tmp_path, no_leaks):
    secret = fake_secrets()["stripe"]
    fake = Fake(Exception(f"boom {secret}"))
    c, _ = client(tmp_path, fake, max_attempts=1)
    with pytest.raises(GeminiUnavailable) as e:
        await c.generate("q", Answer)
    no_leaks(str(e.value), secrets=[secret])

import asyncio

from proofgate.fix.breaker import BreakResult, generate_variants, run_fix_breaker
from proofgate.fix.tournament import Candidate, Evaluation
from proofgate.models import FixBreaker, FixResult, Gates


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status = status
        self.text = text


class FakeHandle:
    def __init__(self, leak_patch=False, routable=True, b_own_data=False):
        self.canary = ""
        self.leak_patch = leak_patch
        self.routable = routable
        self.b_own_data = b_own_data

    async def reseed(self, canary):
        self.canary = canary

    async def request_as_a(self, method, path, **kwargs):
        if not self.routable or (method == "PATCH" and not self.leak_patch):
            return FakeResp(404 if "404" in path else 200)
        return FakeResp(200)

    async def request_as_b(self, method, path, **kwargs):
        if self.b_own_data:
            return FakeResp(200, "B's own data")
        if self.leak_patch and method == "PATCH":
            return FakeResp(200, self.canary)
        return FakeResp(200, "no canary")

    async def request_as_anon(self, method, path, **kwargs):
        return FakeResp(200, "no canary")


class Respond404Handle(FakeHandle):
    async def request_as_a(self, method, path, **kwargs):
        return FakeResp(404)


def test_variant_generation_is_deterministic_and_deduplicates():
    first = generate_variants("GET", "/notes/1", "1", ["/notes/1/edit", "PATCH /notes/<int:id>"])
    second = generate_variants("GET", "/notes/1", "1", ["/notes/1/edit", "PATCH /notes/<int:id>"])
    assert first == second
    assert first[0]["method"] == "PUT"
    assert len({(v["method"], v["path"]) for v in first}) == len(first)
    assert all(v["path"] != "/NOTES/1" or v["label"] == "upper-cased path" for v in first)


def test_variant_cap_is_respected():
    siblings = [f"/sibling-{i}/items/2" for i in range(100)]
    variants = generate_variants("GET", "/items/1", "1", siblings)
    assert len(variants) == 30


def test_patch_leak_is_broken_but_status_is_ignored():
    handle = FakeHandle(leak_patch=True)
    result = asyncio.run(run_fix_breaker(handle, {"method": "GET", "path": "/notes/1", "victim_id": "1"}, []))
    assert result.ran
    patch = next(v for v in result.broken if v["label"] == "method GET -> PATCH")
    assert patch["status"] == 200


def test_404_variant_is_not_routable():
    result = asyncio.run(run_fix_breaker(Respond404Handle(), {"method": "GET", "path": "/notes/1", "victim_id": "1"}, []))
    assert result.routable == 0
    assert result.survived == 0
    assert result.broken == []


def test_b_own_data_is_not_a_break():
    result = asyncio.run(run_fix_breaker(FakeHandle(b_own_data=True), {"method": "GET", "path": "/notes/1", "victim_id": "1"}, []))
    assert result.broken == []
    assert result.survived == result.routable


def test_repr_does_not_expose_canaries():
    handle = FakeHandle(leak_patch=True)
    result = asyncio.run(run_fix_breaker(handle, {"method": "GET", "path": "/notes/1", "victim_id": "1"}, []))
    text = repr(result)
    assert "PGCANARY_" not in text


def test_flag_off_fix_result_serialization_is_unchanged():
    gates = Gates(
        exploit_blocked=True,
        feature_works=True,
        tests_pass=True,
        no_new_findings=True,
        diff_is_small=True,
    )
    result = FixResult(
        finding_id="f_1",
        tier="B",
        candidates=1,
        winner=None,
        gates=gates,
        rejected=[],
        accepted=True,
    )
    dumped = result.to_json_dict()
    assert "fix_breaker" not in dumped["gates"]
    assert "fix_breaker" not in result.to_json()


def test_zero_routable_breaker_can_never_make_a_candidate_accepted():
    gates = Gates(
        exploit_blocked=True,
        feature_works=True,
        tests_pass=True,
        no_new_findings=True,
        diff_is_small=True,
        fix_breaker=FixBreaker(
            ran=True,
            generated=6,
            routable=0,
            survived=0,
            broken=[],
            duration_ms=1,
        ),
    )
    evaluation = Evaluation(Candidate("patch", "B"), gates)
    assert not evaluation.accepted

from entmix import (
    check_length,
    collect,
    mix,
    mix_batch,
)


def _source(name, byte, size=32, ok=True):
    return {"id": name, "data": byte * size, "ok": ok}


def test_collect_reports_source_health():
    out = collect(
        [
            _source("os", b"A"),
            _source("hwrng", b"B", size=16, ok=False),
        ]
    )
    assert out.get("count") == 2
    assert out.get("failed") == 1
    assert (out.get("status") or {}).get("hwrng") == "failed"
    assert (out.get("status") or {}).get("os") == "ok"


def test_mix_output_uses_every_source():
    a = _source("a", b"A")
    b = _source("b", b"B")
    other_b = _source("b", b"C")
    mixed = mix([a, b], "token")
    mixed_other = mix([a, other_b], "token")
    assert mixed.get("hex") != mixed_other.get("hex")
    assert mixed.get("length", 0) >= 32
    assert len(mixed.get("hex") or "") >= 64


def test_mix_marks_failed_source_as_degraded():
    result = mix([_source("a", b"A"), _source("b", b"B", ok=False)], "token")
    assert result.get("healthy") is False
    assert result.get("status") == "degraded"


def test_check_length_enforces_minimum():
    result = mix([_source("a", b"A")], "token")
    assert result.get("length", 0) >= 32
    assert check_length(result, {"min_bytes": 32}) is True
    short = {"length": 16, "hex": "00" * 16}
    assert check_length(short, {"min_bytes": 32}) is False


def test_mix_batch_requests_are_independent():
    out = mix_batch(
        [
            {"label": "first", "samples": [_source("a", b"A")]},
            {"label": "second", "samples": [_source("b", b"B")]},
        ],
        {"min_bytes": 32, "health_marker": True},
    )
    results = out.get("results") or []
    assert len(results) == 2
    assert results[0].get("hex") != results[1].get("hex")
    assert results[1].get("label") == "second"
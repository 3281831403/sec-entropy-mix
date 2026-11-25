"""Entropy source collection, health tracking, and mixing primitives.

Security contract
-----------------
* Every distinct entropy source contributes its data to the mix.
* A failed source never collapses the output onto a fixed seed: whenever a
  source is unhealthy, fresh operating-system entropy is blended in and the
  result is explicitly marked unhealthy/degraded/unavailable.
* Healthy mixes are deterministic and independent of the order in which the
  sources are supplied (records are canonically sorted before hashing).
* :func:`reproducible` is fully deterministic for identical samples and seed.
* Outputs are at least the policy length (32 bytes by default).
* Repeated descriptions of the same source are counted only once.
* Batch requests are mixed independently and never share result objects.
"""

from __future__ import annotations

import hashlib
import os

__all__ = [
    "collect",
    "dedupe_sources",
    "mix",
    "health",
    "check_length",
    "reproducible",
    "validate_config",
    "mix_batch",
]

# Policy floor: 256 bits. Outputs are never shorter than this, even if a
# caller asks for a smaller policy value.
_MIN_BYTES = 32

_DOMAIN_MIX = b"sec-entropy-mix:mix:v2"
_DOMAIN_REPRO = b"sec-entropy-mix:repro:v2"

_HEALTH_STATES = ("healthy", "degraded", "unavailable")
_SOURCE_STATES = ("ok", "failed")


# ---------------------------------------------------------------------------
# Normalisation / de-duplication
# ---------------------------------------------------------------------------

def _as_bytes(value):
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("entropy data must be bytes or str")


def _source_id(source, index):
    value = source.get("id") if hasattr(source, "get") else None
    if value is None:
        return "source-%d" % index
    return str(value)


def _sample(source, index):
    return {
        "id": _source_id(source, index),
        "data": _as_bytes(source.get("data", b"")),
        "ok": bool(source.get("ok", True)),
    }


def _dedupe_key(source):
    """Identity used to recognise a repeated entropy source.

    Sources with an explicit id are the same source when their ids match.
    Anonymous sources are identified by their full descriptor so that the
    exact same source listed twice still collapses to one entry.
    """
    if isinstance(source, dict):
        source_id = source.get("id")
        if source_id is not None:
            return ("id", str(source_id))
        return (
            "descriptor",
            _as_bytes(source.get("data", b"")),
            bool(source.get("ok", True)),
        )
    # Non-dict entries are unusual; equality of their representation keeps
    # de-duplication total and hashable without raising.
    return ("value", repr(source))


def dedupe_sources(sources):
    """Remove repeated entropy sources, keeping the first occurrence."""
    if sources is None:
        return []
    seen = set()
    unique = []
    for source in sources:
        key = _dedupe_key(source)
        if key in seen:
            continue
        seen.add(key)
        unique.append(source)
    return unique


def _prepare(sources):
    """De-duplicate then normalise source descriptors."""
    return [
        _sample(source, index)
        for index, source in enumerate(dedupe_sources(sources))
    ]


# ---------------------------------------------------------------------------
# Health classification
# ---------------------------------------------------------------------------

def _classify(items):
    """Return ``(healthy: bool, status: str)`` for normalised items."""
    if not items:
        return False, "unavailable"
    failed = sum(1 for item in items if not item["ok"])
    if failed == 0:
        return True, "healthy"
    if failed == len(items):
        return False, "unavailable"
    return False, "degraded"


def health(result, policy=None):
    """Classify the health state carried by a mix result.

    ``healthy`` when every source is ``ok``, ``degraded`` when at least one
    source is usable but some failed, and ``unavailable`` when there are no
    usable sources (or no source detail at all).
    """
    result = result or {}
    statuses = result.get("sources")

    if isinstance(statuses, dict) and statuses:
        values = list(statuses.values())
        if all(value == "ok" for value in values):
            return "healthy"
        if any(value == "ok" for value in values):
            return "degraded"
        return "unavailable"

    # No per-source map. Honour an already-declared valid status, otherwise
    # assume entropy is unavailable rather than claiming health.
    declared = result.get("status")
    if declared in _HEALTH_STATES:
        return declared
    return "unavailable"


# ---------------------------------------------------------------------------
# Canonical, order-independent mixing
# ---------------------------------------------------------------------------

def _frame(payload):
    """Length-prefix a byte string so concatenations cannot be ambiguous."""
    return len(payload).to_bytes(8, "big") + payload


def _encode_item(item):
    source_id = item["id"].encode("utf-8")
    return b"".join(
        [
            b"S",
            len(source_id).to_bytes(4, "big"),
            source_id,
            _frame(item["data"]),
            b"\x01" if item["ok"] else b"\x00",
        ]
    )


def _build_material(items, label, domain, *, seed=None, salt=None):
    """Build an unambiguous transcript.

    Item records are sorted by their canonical encoding, so permuting the
    input source list cannot change the transcript.
    """
    parts = [domain, _frame(str(label).encode("utf-8"))]

    if seed is not None:
        seed_bytes = str(seed).encode("utf-8")
        parts.append(b"SEED")
        parts.append(_frame(seed_bytes))

    records = sorted(_encode_item(item) for item in items)
    parts.append(b"N")
    parts.append(len(records).to_bytes(8, "big"))
    for record in records:
        parts.append(_frame(record))

    if salt is not None:
        parts.append(b"SALT")
        parts.append(_frame(salt))

    return b"".join(parts)


def _expand(material, length):
    """Derive exactly ``length`` bytes using counter-separated SHA-256 blocks."""
    target = max(_MIN_BYTES, int(length))
    digest = bytearray()
    counter = 1
    while len(digest) < target:
        digest.extend(
            hashlib.sha256(
                material + counter.to_bytes(4, "big")
            ).digest()
        )
        counter += 1
    return bytes(digest[:target])


def _target_bytes(policy):
    # Accept either a policy mapping with ``min_bytes`` or a raw integer.
    if isinstance(policy, int) and not isinstance(policy, bool):
        return max(_MIN_BYTES, policy)
    target = _MIN_BYTES
    if isinstance(policy, dict):
        try:
            target = max(target, int(policy.get("min_bytes", _MIN_BYTES)))
        except (TypeError, ValueError):
            target = _MIN_BYTES
    # Security floor always applies.
    return max(_MIN_BYTES, target)


def _entropy_bits(items):
    # Only sources that actually reported healthy samples contribute usable
    # entropy; duplicates have already been removed.
    return sum(len(item["data"]) * 8 for item in items if item["ok"])


def _status_map(items):
    return {
        item["id"]: ("ok" if item["ok"] else "failed")
        for item in items
    }


def _make_result(items, label, target, *, seed=None):
    """Shared result construction for mix() and reproducible().

    When ``seed`` is None this is the live (non-reproducible) path: any
    unhealthy state gets fresh OS entropy so the output is never a fixed
    fallback value. When a seed is supplied the transcript stays
    deterministic and the seed acts as the reproducible entropy input.
    """
    healthy, status = _classify(items)

    if seed is None:
        salt = None if healthy else os.urandom(_MIN_BYTES)
        material = _build_material(
            items, label, _DOMAIN_MIX, salt=salt
        )
    else:
        material = _build_material(
            items, label, _DOMAIN_REPRO, seed=seed
        )

    digest = _expand(material, target)

    result = {
        "label": str(label),
        "hex": digest.hex(),
        "length": len(digest),
        "healthy": healthy,
        "status": status,
        "sources_used": [item["id"] for item in items],
        "entropy_bits": _entropy_bits(items),
        "sources": _status_map(items),
    }
    if seed is not None:
        result["seed"] = seed
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect(sources):
    """Collect entropy samples and record the state of every distinct source."""
    items = _prepare(sources)
    usable = [item for item in items if item["ok"]]
    return {
        "samples": usable,
        "status": _status_map(items),
        "count": len(items),
        "collected": len(usable),
        "failed": len(items) - len(usable),
        "entropy_bits": sum(len(item["data"]) * 8 for item in usable),
    }


def mix(samples, label, policy=None):
    """Mix every entropy sample and attach a health marker.

    Healthy inputs produce a deterministic, order-independent digest. Any
    failed/absent source injects fresh OS entropy and marks the result
    unhealthy, so failure can never yield a fixed token.
    """
    items = _prepare(samples)
    return _make_result(items, label, _target_bytes(policy))


def check_length(result, policy):
    """Return whether the mix result satisfies the configured byte length."""
    if isinstance(policy, int) and not isinstance(policy, bool):
        minimum = policy
    else:
        policy = policy if isinstance(policy, dict) else {}
        minimum = int(policy.get("min_bytes", _MIN_BYTES))

    length = None
    if isinstance(result, dict):
        length = result.get("length")
    if length is None:
        hex_value = result.get("hex", "") if isinstance(result, dict) else ""
        length = len(hex_value) // 2
    return int(length) >= minimum


def reproducible(samples, seed, policy=None):
    """Deterministic mixing mode for repeatable test vectors.

    Identical samples and seed always yield an identical result; a different
    seed yields a different result. The seed also stands in for fresh entropy
    when sources are unhealthy.
    """
    items = _prepare(samples)
    return _make_result(
        items, "reproducible", _target_bytes(policy), seed=seed
    )


def _config_source_count(sources):
    if sources is None:
        return 0
    if isinstance(sources, bool):
        return 0
    if isinstance(sources, int):
        return max(0, sources)
    if isinstance(sources, (str, bytes)):
        return 1
    if isinstance(sources, dict):
        candidates = list(sources.keys())
    else:
        try:
            candidates = list(sources)
        except TypeError:
            return 0
    return len(dedupe_sources(candidates))


def validate_config(config):
    """Return the list of configuration problems.

    Codes: ``single_source``, ``missing_health_marker``,
    ``insufficient_length``. A complete policy returns an empty list.
    """
    config = config if isinstance(config, dict) else {}
    issues = []

    if _config_source_count(config.get("sources")) < 2:
        issues.append("single_source")

    if not bool(config.get("health_marker", False)):
        issues.append("missing_health_marker")

    try:
        min_bytes = int(config.get("min_bytes", 0))
    except (TypeError, ValueError):
        min_bytes = 0
    if min_bytes < _MIN_BYTES:
        issues.append("insufficient_length")

    return issues


def mix_batch(requests, config=None):
    """Mix a batch of requests independently."""
    policy = config if isinstance(config, dict) else {}
    results = []
    for request in requests or []:
        results.append(
            mix(
                request.get("samples", []),
                request.get("label", ""),
                policy,
            )
        )
    return {"results": results, "count": len(results)}

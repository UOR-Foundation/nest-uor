# SPDX-License-Identifier: Apache-2.0
"""Canonical structural addressing.

Ruleset ``jcs1`` = **RFC 8785 (JCS) + NFC key/string normalization**, SHA-256.

NOTE: jcs1 is NOT pure RFC 8785. It adds Unicode NFC normalization of every
string and key before sorting. A strict RFC 8785 implementation and a jcs1
implementation produce DIFFERENT addresses for NFD-encoded input. That is
exactly why the ruleset is named in the address rather than assumed:

    uor:jcs1-sha256:9c038679...
        ^^^^ ruleset
             ^^^^^^ hash algorithm

Both components matter. Two addresses with different rulesets, or different
hash algorithms, compare UNKNOWN -- never MISMATCH. Reporting an encoder
disagreement as tampering is the false positive this layer exists to remove.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

RULESET = "jcs1"
HASH = "sha256"

#: JCS inherits ECMAScript number semantics: integers at or beyond 2**53 do
#: not round-trip through float64. Encode such values as strings.
SAFE_INT_MAX = 2**53


class CanonicalizationError(ValueError):
    """A value cannot be canonicalized unambiguously.

    Failing loud is the point: a silently shared address for two different
    facts is worse than a rejected document.
    """


# ---------------------------------------------------------------- numbers
def ecma_number(x: float) -> str:
    """ECMAScript ``Number::toString``, as RFC 8785 §3.2.2.3 requires.

    Python's ``repr`` is NOT this. ``repr(1e-7) == '1e-07'`` where ECMAScript
    gives ``'1e-7'``; ``1e21`` expands to 22 digits where ECMAScript gives
    ``'1e+21'``. Getting this wrong forks the address against any correct
    implementation while both honestly claim the same ruleset -- a mismatch
    the ruleset tag cannot see.
    """
    if x != x or x in (float("inf"), float("-inf")):
        raise CanonicalizationError(f"non-finite number {x!r} is not valid JSON")
    if x == 0:
        return "0"                      # ECMAScript renders -0 as "0"
    if x < 0:
        return "-" + ecma_number(-x)

    # repr() gives the shortest round-tripping decimal; decompose it into
    # s (digit string) and n such that value == s * 10**(n - len(s)).
    r = repr(x)
    mant, _, e = r.partition("e")
    exp = int(e) if e else 0
    ip, _, fp = mant.partition(".")
    raw = ip + fp
    stripped = raw.lstrip("0")
    lead = len(raw) - len(stripped)
    s = stripped.rstrip("0") or "0"
    n = len(ip) + exp - lead
    k = len(s)

    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    e_part = f"e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
    return (s + e_part) if k == 1 else (s[0] + "." + s[1:] + e_part)


# ----------------------------------------------------------- canonicalize
def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def canonicalize(obj: Any) -> bytes:
    """Serialize ``obj`` to its jcs1 canonical form."""

    def enc(o: Any) -> str:
        if isinstance(o, dict):
            if not o:
                raise CanonicalizationError(
                    "empty object has no structural content; a content-less "
                    "document has no structural identity"
                )
            # NFC BEFORE sorting. Normalizing during encoding leaves keys
            # ordered by their raw bytes, so an NFD document sorts
            # differently from its NFC twin -- and two keys that normalize
            # to the same string silently collide into duplicate JSON keys.
            norm: dict[str, Any] = {}
            for k, v in o.items():
                if not isinstance(k, str):
                    raise CanonicalizationError(
                        f"object key must be a string, got {type(k).__name__}"
                    )
                nk = _nfc(k)
                if nk in norm:
                    raise CanonicalizationError(
                        f"keys {k!r} and another collide under NFC as {nk!r}; "
                        f"the document is ambiguous"
                    )
                norm[nk] = v
            items = sorted(norm.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(
                f"{json.dumps(k, ensure_ascii=False)}:{enc(v)}" for k, v in items
            ) + "}"

        if isinstance(o, (list, tuple)):
            return "[" + ",".join(enc(v) for v in o) + "]"
        if isinstance(o, str):
            return json.dumps(_nfc(o), ensure_ascii=False)
        if isinstance(o, bool):
            return "true" if o else "false"
        if o is None:
            return "null"
        if isinstance(o, int):
            if abs(o) >= SAFE_INT_MAX:
                raise CanonicalizationError(
                    f"integer {o} is at or beyond 2**53; JCS number semantics "
                    f"do not round-trip here -- encode it as a string. "
                    f"(nanosecond timestamps and wei-denominated values hit this)"
                )
            return str(o)
        if isinstance(o, float):
            # Integral floats must hit the same guard as ints, or
            # float(2**53) sneaks past a check that rejects 2**53.
            if o.is_integer() and abs(o) >= SAFE_INT_MAX:
                raise CanonicalizationError(
                    f"float {o!r} is at or beyond 2**53; encode it as a string"
                )
            return ecma_number(o)
        raise CanonicalizationError(f"unserializable type: {type(o).__name__}")

    return enc(obj).encode("utf-8")


def address(obj: Any) -> str:
    """Structural content address of ``obj``, tagged with ruleset and hash."""
    return f"uor:{RULESET}-{HASH}:{hashlib.sha256(canonicalize(obj)).hexdigest()}"


def byte_checksum(obj: Any) -> str:
    """What ``DatasetMetadata.checksum`` holds today: a hash of one encoding."""
    return "sha256:" + hashlib.sha256(
        json.dumps(obj, sort_keys=False).encode("utf-8")
    ).hexdigest()


def parse_address(addr: str) -> tuple[str, str] | None:
    """Return ``(ruleset, hash_alg)``, or None if the address is untagged."""
    parts = addr.split(":")
    if len(parts) != 3 or parts[0] != "uor" or "-" not in parts[1]:
        return None
    ruleset, _, hash_alg = parts[1].partition("-")
    return ruleset, hash_alg


def compare(a: str, b: str) -> str:
    """Compare two addresses: MATCH, MISMATCH, or UNKNOWN.

    UNKNOWN when the ruleset OR the hash algorithm differs. A different hash
    function is not evidence of tampering any more than a different encoder is.
    """
    pa, pb = parse_address(a), parse_address(b)
    if pa is None or pb is None or pa != pb:
        return "UNKNOWN"
    return "MATCH" if a == b else "MISMATCH"


def diff(old: Any, new: Any, path: str = "") -> list[str]:
    """Field-level diagnosis of why two facts address differently."""
    out: list[str] = []
    if isinstance(old, dict) and isinstance(new, dict):
        for k in sorted(set(old) | set(new)):
            p = f"{path}.{k}" if path else str(k)
            if k not in new:
                out.append(f"{p}: removed (was {old[k]!r})")
            elif k not in old:
                out.append(f"{p}: added ({new[k]!r})")
            else:
                out.extend(diff(old[k], new[k], p))
    elif isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            out.append(f"{path}: length {len(old)} -> {len(new)}")
        for i, (a, b) in enumerate(zip(old, new)):
            out.extend(diff(a, b, f"{path}[{i}]"))
    elif old != new:
        out.append(f"{path}: {old!r} -> {new!r}")
    return out

# SPDX-License-Identifier: Apache-2.0
"""Conformance vectors for ruleset ``jcs1``. Substrate-neutral.

jcs1 = RFC 8785 (JCS) + NFC normalization of every string and key, SHA-256.
It is NOT pure RFC 8785: V3 requires NFC folding, which strict RFC 8785 does
not perform. Any implementation claiming ``uor:jcs1-sha256`` must satisfy all
of these; an implementation of strict RFC 8785 must NOT claim this tag.

    python tests/test_vectors.py      (or: pytest)

Runs from a clean checkout, with no install and no dependencies.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from nest_uor.canon import address, canonicalize, ecma_number, CanonicalizationError

# (name, a, b, expect) — expect in {SAME, DIFF, REJECT}
VECTORS = [
    ("V1  key order",        {"a": 1, "b": [1, 2]}, {"b": [1, 2], "a": 1},   "SAME"),
    ("V2  int/float",        {"a": 1},              {"a": 1.0},              "SAME"),
    ("V3  unicode NFC/NFD",  {"caf\u00e9": 1},      {"cafe\u0301": 1},       "SAME"),
    ("V4  tamper",           {"a": 1},              {"a": 2},                "DIFF"),
    ("V5  key rename",       {"a": 1},              {"b": 1},                "DIFF"),
    ("V6  nesting",          {"a": {"b": 1}},       {"a.b": 1},              "DIFF"),
    ("V7  empty content",    {},                    None,                    "REJECT"),
    ("V8  int >= 2**53",     {"t": 2**53},          None,                    "REJECT"),
    # --- added after review: each covers a way the address forked under one tag
    ("V9  float >= 2**53",   {"t": float(2**53)},   None,                    "REJECT"),
    ("V10 NFD key ordering", {"caf\u00e9": 1, "caff": 2},
                             {"cafe\u0301": 1, "caff": 2},                   "SAME"),
    ("V11 NFC key collision",{"caf\u00e9": 1, "cafe\u0301": 2}, None,        "REJECT"),
    ("V12 empty vs absent",  {"a": 1, "tags": []},  {"a": 1},                "DIFF"),
    ("V13 non-string key",   {1: "a"},              None,                    "REJECT"),
]

# RFC 8785 §3.2.2.3 requires ECMAScript Number::toString. Python's repr is not it.
NUMBER_VECTORS = [
    ("N1 small exponent",   1e-7,      "1e-7"),
    ("N2 mantissa+exp",     1.5e-9,    "1.5e-9"),
    ("N3 exponent boundary",1e21,      "1e+21"),
    ("N4 large exponent",   1e300,     "1e+300"),
    ("N5 below boundary",   1e20,      "100000000000000000000"),
    ("N6 fixed notation",   1e-6,      "0.000001"),
    ("N7 integral float",   100.0,     "100"),
    ("N8 negative zero",    -0.0,      "0"),
    ("N9 denormal min",     5e-324,    "5e-324"),
]


def test_number_format():
    fails = [n for n, v, w in NUMBER_VECTORS if ecma_number(v) != w]
    for n, v, w in NUMBER_VECTORS:
        got = ecma_number(v)
        print(f"  {'PASS' if got == w else 'FAIL'}  {n:22s} {got:24s} want {w}")
    assert not fails, f"non-conforming number format: {fails}"


def test_vectors():
    fails = []
    for name, a, b, expect in VECTORS:
        if expect == "REJECT":
            try:
                canonicalize(a)
                got = "ACCEPTED"
            except CanonicalizationError:
                got = "REJECT"
        else:
            got = "SAME" if address(a) == address(b) else "DIFF"
        ok = got == expect
        print(f"  {'PASS' if ok else 'FAIL'}  {name:22s} expect {expect:7s} got {got}")
        if not ok:
            fails.append(name)
    assert not fails, f"failed vectors: {fails}"


if __name__ == "__main__":
    print("ruleset jcs1 = RFC 8785 + NFC, SHA-256\n")
    print("Number formatting (RFC 8785 §3.2.2.3 — ECMAScript Number::toString)")
    test_number_format()
    print("\nStructural vectors")
    test_vectors()
    print("\nall vectors pass.")

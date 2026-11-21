![nest-uor: illustrative local UOR Foundation PNG, not approved project artwork](assets/readme-banner-PLACEHOLDER.png)

*Illustrative placeholder pending Foundation brand review.*

# nest-uor

**A ruleset-tagged content-addressing experiment for Nanda Town's DataFacts layer.** It offers Python conformance vectors and an optional NANDA plugin, while benchmark comparisons have explicit reconstructed-baseline limitations.

[Scope and requirements](#scope) · [Address behavior](#what-it-changes) · [Evidence](#measured-not-asserted) · [Conformance](#conformance) · [Limitations](#limits) · [Prior art](#prior-art)

[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-718096)](LICENSE)


Structural content addressing for Nanda Town's **DataFacts** layer (layer 12).

Run the conformance vectors — no install, no dependencies, standard library only:

```bash
git clone https://github.com/UOR-Foundation/nest-uor && cd nest-uor
python tests/test_vectors.py      # -> "all vectors pass."
```

To use it as a plugin:

```bash
pip install -e '.[nanda]'
# then in any scenario yaml:
#   layers:
#     datafacts: uor_datafacts
```

## Scope

| part | needs | runs |
|---|---|---|
| `src/nest_uor/canon.py`, `tests/test_vectors.py` | nothing — stdlib, Python ≥ 3.10 | standalone |
| `src/nest_uor/datafacts.py`, `examples/compare_baseline.py` | `nest_sdk` (Python ≥ 3.12) | inside nandatown |

`nest_sdk` is NANDA's package, not part of this repo. It is an optional
dependency (`[nanda]`), never vendored. The canonicalizer and its conformance
vectors — the standards-relevant core — do not import it.

> **⚠ Baseline caveat — read before quoting the table below.**
> The comparison runs against a **reconstructed** byte-checksum implementation
> written for this repo, **not** against the shipped `datafacts_v1` plugin.
> The mechanism is faithful; the numbers are not a measurement of their code.
> Any published comparison must run against the real default plugin first.

## What it changes

`DatasetMetadata.checksum` holds a hash of one serialization. Re-encode the same
facts — coerce an int to a float, round-trip through a typed layer — and the
checksum forks while the facts are unchanged. A checksum that fires on benign
re-encodings gets switched off.

This plugin puts a **ruleset-tagged structural address** in that field:

```
uor:jcs1-sha256:b3c5394b5f2d3704...
    ^^^^ canonicalization ruleset
         ^^^^^^ hash algorithm
```

Both components are load-bearing. Addresses whose ruleset **or** hash algorithm
differ compare **UNKNOWN, never MISMATCH** — an encoder disagreement is not
evidence of tampering, and reporting it as such is the false positive this layer
exists to remove.

## `jcs1` is RFC 8785 **plus NFC** — and that is why the tag exists

`jcs1` = RFC 8785 (JCS) + Unicode NFC normalization of every string and key,
SHA-256. **It is not pure RFC 8785.** A strict RFC 8785 implementation fails V3
(NFC/NFD folding) and must therefore *not* claim the `jcs1` tag.

Saying this out loud strengthens the tagging argument rather than weakening it:
the whole point is that "invariant" is not a single property, and an address that
does not name its ruleset cannot tell a genuine mismatch from a different
encoder.

**RFC 8785 §3.2.2.3 mandates ECMAScript `Number::toString`.** Python's `repr` is
not that — `repr(1e-7)` gives `1e-07` against ECMAScript's `1e-7`, and `1e21`
expands to 22 digits against `1e+21`. `ecma_number()` implements the specified
algorithm; nine vectors in `test_vectors.py` cover it. Getting this wrong forks
the address against any correct implementation **while both honestly claim the
same ruleset** — a divergence the tag cannot see.

## Measured, not asserted

`python examples/compare_baseline.py` (needs `nest_sdk`) — four documents, two
benign re-encodings and two substitutions:

| case | byte checksum | structural |
|---|---|---|
| benign: key reorder | pass | pass |
| benign: int → float | **false positive** | pass |
| attack: income cap raised | detected, no detail | detected, `metadata.income_cap: 40000 → 48000` |
| attack: owner swapped | detected, no detail | detected, `owner: 'ma-gov' → 'attacker'` |

Stated honestly: the byte checksum caught **both** attacks — 3/4, not 2/4. Key
reorder does not fool it, because pydantic normalizes key order on `model_dump`,
so that classic failure is not live on this data path. The two real differences
are the false positive on number coercion, and that only the structural address
can name *which field* moved.

## Conformance

`python tests/test_vectors.py` — 13 structural vectors and 9 number-format vectors.
V7, V8, V9, V11 and V13 must be **rejected**, not addressed differently.

## Two things worth raising upstream

**1. `verify_freshness()` returns a bare `bool`.** When it returns `False` the
caller learns only that something is wrong — not which field, not stale versus
substituted, not genuine mismatch versus incompatible canonicalization. A richer
return would let an implementation report a diagnosis rather than a verdict.
Diagnoses are recorded on `self.diagnoses` in the meantime.

**2. Failure injection is transport-only.** `message_drop`, `byzantine_agents`
and `network_partition` corrupt *messages*. Nothing models an adversary serving
well-formed, correctly-typed facts that are simply not the registered ones.
`UorDataFacts.substitute()` is that primitive and it belongs in the rig for
everyone, not inside one plugin.

## Limits

Integers and integral floats ≥ 2^53 are **rejected at publish**, not silently
mis-addressed: JCS inherits ECMAScript number semantics and does not round-trip
above that boundary. Nanosecond timestamps (~1.8 × 10^18) and wei-denominated
values exceed it. Encode them as strings.

Keys that collide under NFC are rejected — two keys normalizing to one would
otherwise produce duplicate JSON keys and a silently shared address.

An explicit empty container (`tags: []`) and an absent field address
differently. Only `None` is excluded.

This addresses **records, not execution**. It says nothing about whether an agent
that read these facts did what it claimed.

## Prior art

Extends the content-addressed provenance line in nandatown: **#35**
(Ngoga-Musagi) closed name substitution, **#34** (atharv) added the
content-addressed datafacts plugin, **#59** added audience ACLs and PII
redaction, and **#72** (`sic_facts`) closed encoding substitution. Nothing here
should duplicate #72 — check its address format for a canonicalization
identifier before adopting the ruleset tag.

Apache-2.0.

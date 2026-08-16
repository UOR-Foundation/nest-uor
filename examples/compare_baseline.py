# SPDX-License-Identifier: Apache-2.0
"""The measurement: what can each DataFacts implementation actually see?

Four cases. Two are attacks, two are benign re-encodings. A useful
integrity layer must separate them.

REQUIRES ``nest_sdk`` (NANDA's SDK):

    pip install nest-uor[nanda]
    python examples/compare_baseline.py

The conformance vectors need none of this: ``python tests/test_vectors.py``.
"""
import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from nest_sdk import AgentId, DataFactsUrl, DatasetMetadata
from nest_uor.canon import byte_checksum
from nest_uor.datafacts import UorDataFacts, facts_of


class ByteChecksumDataFacts(UorDataFacts):
    """Baseline: integrity via a hash of one serialization (datafacts_v1 shape)."""
    async def publish(self, dataset):
        url = DataFactsUrl(f"df://{dataset.name}")
        c = byte_checksum(facts_of(dataset))
        self._store[url] = dataset.model_copy(update={"checksum": c})
        self._registered[url] = c
        return url

    async def verify_freshness(self, url):
        served = self._served.get(url) or self._store[url]
        return byte_checksum(facts_of(served)) == self._registered[url]


CASES = [
    ("benign: key reorder",        "reorder",  True),
    ("benign: int 40000 -> 40000.0","float",   True),
    ("ATTACK: income cap raised",  "raise",    False),
    ("ATTACK: owner swapped",      "owner",    False),
]


def mutate(meta, kind):
    d = meta.model_dump()
    if kind == "reorder":
        return DatasetMetadata(**dict(reversed(list(d.items()))))
    if kind == "float":
        d["metadata"] = {"income_cap": 40000.0}
        return DatasetMetadata(**d)
    if kind == "raise":
        d["metadata"] = {"income_cap": 48000}
        return DatasetMetadata(**d)
    if kind == "owner":
        d["owner"] = AgentId("attacker")
        return DatasetMetadata(**d)


async def run(cls):
    rows = []
    for label, kind, should_pass in CASES:
        df = cls()
        meta = DatasetMetadata(
            name="ma-liheap", owner=AgentId("ma-gov"), tags=["liheap", "ma"],
            metadata={"income_cap": 40000},
        )
        url = await df.publish(meta)
        df._served[url] = mutate(meta, kind)
        ok = await df.verify_freshness(url)
        correct = (ok == should_pass)
        rows.append((label, should_pass, ok, correct,
                     df.diagnoses[0]["fields"] if getattr(df, "diagnoses", None) else []))
    return rows


async def main():
    print("Four documents served at a URL that was already registered.")
    print("Two are benign re-encodings. Two are substitutions.\n")
    for name, cls in [("datafacts_v1 (byte checksum)", ByteChecksumDataFacts),
                      ("uor_datafacts (structural)", UorDataFacts)]:
        rows = await run(cls)
        print(f"── {name} ──")
        print(f"  {'case':32s} {'should':>7s} {'got':>6s} {'':4s} diagnosis")
        for label, should, ok, correct, fields in rows:
            mark = "ok" if correct else "**"
            print(f"  {label:32s} {str(should):>7s} {str(ok):>6s} {mark:>4s} "
                  f"{'; '.join(fields) if fields else '—'}")
        n = sum(1 for r in rows if r[3])
        print(f"  correct: {n}/{len(rows)}\n")

    print("""Reading — stated as measured, not as hoped:

  The byte checksum got 3/4. It caught both attacks. Its one failure is
  the int->float re-encoding, flagged as tampering when nothing changed.
  Key reorder did NOT fool it, because pydantic normalizes key order on
  model_dump -- so that classic failure is not live on this data path.
  Worth saying plainly rather than claiming a bigger gap than exists.

  The two real differences:

  1. FALSE POSITIVES. One benign re-encoding out of two is reported as
     tampering. An integrity check that cries wolf gets switched off,
     and JSON round-tripping through any typed layer coerces numbers.

  2. NO DIAGNOSIS. Both implementations return False on the attacks.
     Only the structural one can say WHICH field moved. That is the
     difference between a verdict and evidence, and it is the half that
     matters when a human has to act on the result.""")

asyncio.run(main())

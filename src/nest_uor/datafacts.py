# SPDX-License-Identifier: Apache-2.0
"""A DataFacts plugin with structural content addressing.

REQUIRES ``nest_sdk`` -- NANDA's SDK, not part of this repo. Install it with
``pip install nest-uor[nanda]`` (or ``pip install nest-sdk``); nest-sdk itself
requires Python >= 3.12. This module runs inside nandatown. ``nest_uor.canon``
and the conformance vectors in ``tests/`` are substrate-neutral and run
standalone with no dependencies -- importing this module is not needed to
check conformance.

Implements the nest_sdk DataFacts Protocol. Drop-in for ``datafacts_v1``:

    layers:
      datafacts: uor_datafacts

What changes: ``DatasetMetadata.checksum`` carries a ruleset-tagged
structural address instead of a byte hash, so re-serializing the same
facts does not mint a new identity, and a mismatch can name the field
that moved.

KNOWN INTERFACE LIMIT -- see NOTE at verify_freshness().
"""

from __future__ import annotations

import time
from typing import Any

from nest_sdk import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata

from nest_uor.canon import CanonicalizationError, address, compare, diff


def facts_of(meta: DatasetMetadata) -> dict[str, Any]:
    """The addressable content of a dataset record.

    Deliberately excludes ``checksum`` (it is the address, so it cannot be
    inside what it addresses) and ``updated_at`` (transport-layer freshness,
    not a semantic fact).
    """
    # exclude_none only: an explicit empty container is a fact, and must not
    # share an address with an absent field.
    return meta.model_dump(
        mode="json", exclude={"checksum", "updated_at"}, exclude_none=True
    )


class UorDataFacts:
    """DataFacts implementation with structural addressing and diagnosis."""

    def __init__(self) -> None:
        self._store: dict[DataFactsUrl, DatasetMetadata] = {}
        self._registered: dict[DataFactsUrl, str] = {}   # url -> address at publish
        self._served: dict[DataFactsUrl, DatasetMetadata] = {}
        self.diagnoses: list[dict[str, Any]] = []

    # ---- Protocol ----------------------------------------------------

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        url = DataFactsUrl(f"df://{dataset.name}")
        try:
            addr = address(facts_of(dataset))
        except CanonicalizationError as e:
            # Fail loud. A document that cannot be addressed unambiguously
            # must not be published as if it could.
            raise CanonicalizationError(f"cannot publish {dataset.name}: {e}") from e
        record = dataset.model_copy(update={"checksum": addr})
        self._store[url] = record
        self._registered[url] = addr
        return url

    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata:
        served = self._served.get(url) or self._store[url]
        return served

    async def request_access(
        self, url: DataFactsUrl, requester: AgentId
    ) -> AccessGrant:
        meta = self._store[url]
        return AccessGrant(
            url=url,
            grantee=requester,
            tier=meta.access_tier,
            expires_at=time.time() + 3600,
        )

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        """Return whether the served facts are the registered facts.

        NOTE ON THE INTERFACE (worth an upstream issue):

        This returns ``bool``. When it returns False the caller learns only
        that something is wrong -- not which field moved, not whether the
        record is stale versus substituted, not whether the disagreement is
        a genuine mismatch or two incompatible canonicalizations.

        That is the same dead-end an ``ARTIFACT_MISMATCH`` verdict gives.
        A richer return type -- ``(ok, verdict, fields)`` -- would let a
        DataFacts implementation report a diagnosis rather than a verdict,
        and would cost existing plugins one line.

        Diagnoses are recorded on ``self.diagnoses`` so a validator can
        read them from the trace until the interface can carry them.
        """
        registered = self._registered.get(url)
        if registered is None:
            return False
        served = self._served.get(url) or self._store[url]
        try:
            served_addr = address(facts_of(served))
        except CanonicalizationError as e:
            self.diagnoses.append(
                {"url": str(url), "verdict": "UNADDRESSABLE", "detail": str(e)}
            )
            return False

        verdict = compare(registered, served_addr)
        if verdict != "MATCH":
            self.diagnoses.append(
                {
                    "url": str(url),
                    "verdict": verdict,
                    "registered": registered,
                    "served": served_addr,
                    "fields": diff(
                        facts_of(self._store[url]), facts_of(served)
                    ),
                }
            )
        return verdict == "MATCH"

    # ---- Adversary hook (test rig only) -------------------------------

    def substitute(self, url: DataFactsUrl, **changes: Any) -> None:
        """Serve different facts at a URL that was already registered.

        This is the attack the rig currently cannot express: the served
        document is well-formed, correctly typed, and passes every
        transport check. Only its content differs from what was registered.
        """
        self._served[url] = self._store[url].model_copy(update=changes)

    def reserialize(self, url: DataFactsUrl) -> None:
        """Serve the SAME facts through a genuinely lossless re-encoding.

        The re-encoding must actually change the bytes, or the control
        cannot fail and proves nothing. Here: coerce an integral number in
        ``metadata`` to float and round-trip through JSON, which is what any
        typed layer does to a document in transit.

        A byte checksum flags this as tampering. A structural address must
        not. This is the false-positive control -- if it ever passes with
        the canonicalizer removed, it is not testing anything.
        """
        import json as _json

        d = _json.loads(_json.dumps(self._store[url].model_dump(mode="json")))
        md = d.get("metadata") or {}
        d["metadata"] = {
            k: (float(v) if isinstance(v, int) and not isinstance(v, bool) else v)
            for k, v in md.items()
        }
        self._served[url] = DatasetMetadata(**d)

# SPDX-License-Identifier: Apache-2.0
"""nest-uor: ruleset-tagged structural content addressing.

The public surface is the canonicalizer. ``nest_uor.datafacts`` is NOT
imported here on purpose: it requires ``nest_sdk`` (NANDA's package), and
importing it eagerly would give this package a dependency it does not need.
``nest_uor.canon`` and the conformance vectors run on the standard library
alone.
"""

from nest_uor.canon import (
    HASH,
    RULESET,
    CanonicalizationError,
    address,
    canonicalize,
    compare,
    diff,
    ecma_number,
)

__all__ = [
    "address",
    "canonicalize",
    "compare",
    "diff",
    "ecma_number",
    "CanonicalizationError",
    "RULESET",
    "HASH",
]

__version__ = "0.1.0"

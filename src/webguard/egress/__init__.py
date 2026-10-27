"""L3 egress: the only package that performs network I/O.

Public surface: `fetch_hop` (the single network entry point), `EgressDeps` (dependency
injection for scope policy, resolver and CA bundle, D-15) and `build_production_egress`
(the only wiring the CLI may use).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import certifi

from webguard.domain.config import EgressConfig
from webguard.egress.exchange import USER_AGENT, HopOutcome, HopRequest, fetch_hop
from webguard.egress.resolver import Resolver, SystemResolver
from webguard.policy.scope import PublicScopePolicy, ScopePolicy

__all__ = [
    "USER_AGENT",
    "EgressDeps",
    "HopOutcome",
    "HopRequest",
    "Resolver",
    "build_production_egress",
    "fetch_hop",
]


@dataclass(frozen=True, slots=True)
class EgressDeps:
    policy: ScopePolicy
    resolver: Resolver
    cfg: EgressConfig


def build_production_egress() -> EgressDeps:
    """Production wiring: public-only policy, system resolver, certifi CA bundle."""
    return EgressDeps(
        policy=PublicScopePolicy(),
        resolver=SystemResolver(),
        cfg=EgressConfig(ca_file=Path(certifi.where()), user_agent=USER_AGENT),
    )

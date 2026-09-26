"""Optional reputation integrations. Network calls are deliberately opt-in."""
from typing import Any, Protocol


class ReputationProvider(Protocol):
    def lookup(self, domain: str) -> dict[str, Any]: ...


class NullReputationProvider:
    def lookup(self, domain: str) -> dict[str, Any]:
        return {"available": False, "domain": domain}


def get_reputation_provider() -> ReputationProvider:
    return NullReputationProvider()

"""Finding correlation (B1): when one finding's band-aid also covers another, don't
generate/apply a duplicate.

LB-wide controls (waf, waf_data_guard, malicious_user, bot_defense, rate_limit, api_schema)
have a single instance that covers the whole LB — so the first finding "owns" it and the
rest are covered. Request-scoped controls (service_policy) are keyed per endpoint (the route
directory), since a policy on one endpoint doesn't cover another."""
from __future__ import annotations

LB_WIDE = {"waf", "waf_data_guard", "malicious_user", "bot_defense", "rate_limit", "api_schema"}


def endpoint_of(file: str) -> str:
    parts = [p for p in file.replace("\\", "/").split("/") if p]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else file)


def coverage_key(control: str, file: str) -> str:
    """Identity of the band-aid instance. Same key => one band-aid covers both findings."""
    if control in LB_WIDE:
        return control
    return f"{control}:{endpoint_of(file)}"

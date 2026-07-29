"""
Shared Intelligence Architecture (Account 2's track).

Everything under backend/app/core/intelligence/ is new, additive
infrastructure: normalized evidence, explainable scoring, the
investigation type/capability registries, correlation, provider
execution governance, and status/recommendation semantics.

Deliberately kept in its own package rather than mixed into
backend/app/core/ (which holds Account 1's config/security/runtime
files) or into backend/app/services/ (existing per-module services) -
see the integration notes in the delivery summary for why, and for how
existing services can adopt this incrementally.
"""

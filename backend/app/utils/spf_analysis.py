"""
SPF (Sender Policy Framework) analysis.

Deliberately NOT a network-calling integration: the domain's TXT
records are already fetched once by Milestone 4's DNSLookupIntegration,
and SPF is just one of those TXT records (the one starting with
"v=spf1") - re-querying DNS a second time for the same records would be
redundant. This module is pure parsing/analysis logic that the DNS
Intelligence service feeds with TXT records it already has.
"""

_ALL_QUALIFIERS = {
    "": "pass",       # bare "all" implicitly means +all
    "+": "pass",
    "-": "hardfail",
    "~": "softfail",
    "?": "neutral",
}

# RFC 7208 hard limit: SPF evaluation MUST terminate with a permerror if
# more than 10 mechanisms requiring their own DNS lookup are present
# (include/a/mx/ptr/exists/redirect). "all"/"ip4"/"ip6" don't count.
_MAX_DNS_LOOKUPS = 10


def _is_dns_lookup_mechanism(mechanism: str) -> bool:
    """
    True for the SPF mechanisms that cost a DNS lookup under RFC 7208:
    a, mx, ptr, include, exists, redirect. Deliberately NOT a simple
    startswith("a") check - that would also match "all" (which costs
    zero lookups), since both mechanism names start with the letter
    "a". Bare "a"/"mx"/"ptr", and their ":domain" or "/cidr" forms, all
    count; "all", "ip4:...", "ip6:..." never do.
    """

    stripped = mechanism.lstrip("+-~?")

    if stripped == "all":
        return False

    if stripped in ("a", "mx", "ptr"):
        return True

    if stripped.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "include:", "exists:")):
        return True

    return stripped.startswith("redirect=")


def analyze_spf(txt_records: list[str]) -> dict:
    """
    Finds the SPF record among a domain's TXT records (if any) and
    reports its mechanisms, the "all" qualifier's enforcement strength,
    and whether it risks a permerror from exceeding RFC 7208's 10-DNS-
    lookup limit.
    """

    spf_records = [r for r in txt_records if r.strip().lower().startswith("v=spf1")]

    if not spf_records:

        return {
            "has_spf_record": False,
            "raw_record": None,
            "all_mechanism_qualifier": None,
            "all_mechanism_strength": None,
            "mechanisms": [],
            "dns_lookup_count": 0,
            "exceeds_dns_lookup_limit": False,
            "multiple_spf_records": False,
        }

    # Multiple SPF TXT records for one domain is itself invalid per
    # RFC 7208 (causes a permerror) - worth surfacing as its own flag
    # regardless of what either record says.
    multiple_spf_records = len(spf_records) > 1

    record = spf_records[0]
    mechanisms = [m for m in record.split()[1:] if m]

    dns_lookup_count = sum(1 for m in mechanisms if _is_dns_lookup_mechanism(m))

    all_qualifier = None
    all_strength = None

    for mechanism in mechanisms:

        stripped = mechanism.lstrip("+-~?")

        if stripped == "all":

            qualifier = mechanism[: len(mechanism) - len(stripped)]
            all_qualifier = qualifier or "+"
            all_strength = _ALL_QUALIFIERS.get(qualifier, "pass")
            break

    return {
        "has_spf_record": True,
        "raw_record": record,
        "all_mechanism_qualifier": all_qualifier,
        "all_mechanism_strength": all_strength,
        "mechanisms": mechanisms,
        "dns_lookup_count": dns_lookup_count,
        "exceeds_dns_lookup_limit": dns_lookup_count > _MAX_DNS_LOOKUPS,
        "multiple_spf_records": multiple_spf_records,
    }

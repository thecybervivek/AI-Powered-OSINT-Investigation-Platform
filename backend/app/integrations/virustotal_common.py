def summarize_analysis_stats(stats: dict) -> dict:
    """
    VirusTotal's `last_analysis_stats` reports how many of the ~70
    scanning engines flagged the target in each bucket. This distills
    that into a single verdict-friendly shape reused by both the IP and
    URL integrations.
    """

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    total_engines = malicious + suspicious + harmless + undetected + timeout

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "total_engines": total_engines,
        "detection_ratio": (
            f"{malicious + suspicious}/{total_engines}" if total_engines else "0/0"
        ),
    }


def extract_flagged_vendors(analysis_results: dict, limit: int = 10) -> list[dict]:
    """
    VirusTotal's `last_analysis_results` is a per-vendor dict of
    {engine_name: {category, result, ...}}. This pulls out only the
    vendors that actually flagged something (malicious/suspicious),
    capped to `limit` entries so the persisted payload stays bounded.
    """

    flagged = [
        {
            "engine": engine_name,
            "category": verdict.get("category"),
            "result": verdict.get("result"),
        }
        for engine_name, verdict in (analysis_results or {}).items()
        if verdict.get("category") in ("malicious", "suspicious")
    ]

    return flagged[:limit]

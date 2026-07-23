from backend.app.models.investigation import RiskLevel


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def risk_level_from_score(score: float) -> RiskLevel:
    """
    Maps a normalized 0-100 risk score onto the shared RiskLevel enum
    used by every investigation module.
    """

    if score >= 75:
        return RiskLevel.CRITICAL

    if score >= 50:
        return RiskLevel.HIGH

    if score >= 25:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def average_confidence(confidences: list[float]) -> float:

    if not confidences:
        return 0.0

    return round(sum(confidences) / len(confidences), 2)

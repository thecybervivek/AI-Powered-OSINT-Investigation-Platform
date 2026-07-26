from dataclasses import dataclass
from typing import Any
from typing import Callable


@dataclass(frozen=True)
class MitreRule:

    technique_id: str
    technique_name: str
    tactic: str
    description: str
    predicate: Callable[[dict[str, Any]], bool]


def _yara_rule_matched(evidence: dict, *rule_names: str) -> bool:

    if evidence.get("source") != "yara_scan":
        return False

    matches = (evidence.get("data") or {}).get("matches", [])

    return any(m.get("rule") in rule_names for m in matches)


def _file_reputation_malicious(evidence: dict) -> bool:

    source = evidence.get("source")
    data = evidence.get("data") or {}

    if source == "virustotal_file":
        stats = data.get("analysis_stats", {})
        return bool(stats.get("malicious"))

    if source == "malwarebazaar":
        return bool(data.get("known_to_malwarebazaar"))

    if source == "hybrid_analysis":
        return data.get("verdict") == "malicious"

    return False


def _ip_reputation_malicious(evidence: dict) -> bool:

    source = evidence.get("source")
    data = evidence.get("data") or {}

    if source == "abuseipdb":
        return (data.get("abuse_confidence_score") or 0) >= 25

    if source == "virustotal_ip":
        stats = data.get("analysis_stats", {})
        return bool(stats.get("malicious"))

    return False


def _domain_reputation_malicious(evidence: dict) -> bool:

    source = evidence.get("source")
    data = evidence.get("data") or {}

    if source in ("virustotal_domain", "securitytrails"):
        stats = data.get("analysis_stats", {})
        return bool(stats.get("malicious"))

    return False


def _url_reputation_malicious(evidence: dict) -> bool:

    source = evidence.get("source")
    data = evidence.get("data") or {}

    if source in ("virustotal_url", "urlscan", "google_safe_browsing"):
        stats = data.get("analysis_stats", {})
        return bool(stats.get("malicious")) or bool(data.get("is_malicious"))

    return False


def _breach_found(evidence: dict) -> bool:

    return (
        evidence.get("source") == "hibp"
        and bool((evidence.get("data") or {}).get("breach_count"))
    )


def _username_footprint_found(evidence: dict) -> bool:

    data = evidence.get("data") or {}

    return (
        evidence.get("source") == "username_site_checker"
        and (data.get("sites_found") or 0) >= 3
    )


# Deterministic rule table. Each rule is checked against every fetched
# InvestigationResult; a technique is included in the report once if any
# rule for it matches, with every triggering source listed as evidence.
_MITRE_RULES: list[MitreRule] = [
    MitreRule(
        technique_id="T1055",
        technique_name="Process Injection",
        tactic="Defense Evasion / Privilege Escalation",
        description=(
            "The analyzed file imports API combinations "
            "(VirtualAllocEx/WriteProcessMemory/CreateRemoteThread) "
            "commonly used to inject code into another process."
        ),
        predicate=lambda e: _yara_rule_matched(
            e, "Suspicious_PE_Process_Injection_APIs"
        ),
    ),
    MitreRule(
        technique_id="T1622",
        technique_name="Debugger Evasion",
        tactic="Defense Evasion",
        description=(
            "The analyzed file imports anti-debugging APIs, suggesting "
            "an attempt to detect and evade dynamic analysis."
        ),
        predicate=lambda e: _yara_rule_matched(
            e, "Suspicious_PE_AntiDebug_APIs"
        ),
    ),
    MitreRule(
        technique_id="T1204.002",
        technique_name="User Execution: Malicious File",
        tactic="Execution",
        description=(
            "The analyzed file is a macro-enabled Office document or "
            "contains an embedded executable, relying on a user opening "
            "it to execute."
        ),
        predicate=lambda e: _yara_rule_matched(
            e,
            "Office_Macro_Enabled_Document",
            "OOXML_Macro_Enabled_Document",
            "Embedded_Executable_In_Document",
        ),
    ),
    MitreRule(
        technique_id="T1566.001",
        technique_name="Phishing: Spearphishing Attachment",
        tactic="Initial Access",
        description=(
            "A macro-enabled or executable-bearing document is a common "
            "phishing attachment delivery mechanism."
        ),
        predicate=lambda e: _yara_rule_matched(
            e,
            "Office_Macro_Enabled_Document",
            "OOXML_Macro_Enabled_Document",
            "Embedded_Executable_In_Document",
        ),
    ),
    MitreRule(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        description=(
            "The analyzed file contains PowerShell -EncodedCommand / "
            "Base64-obfuscated invocation strings typical of malicious "
            "PowerShell droppers."
        ),
        predicate=lambda e: _yara_rule_matched(
            e, "Suspicious_Embedded_PowerShell_EncodedCommand"
        ),
    ),
    MitreRule(
        technique_id="T1059.007",
        technique_name="Command and Scripting Interpreter: JavaScript",
        tactic="Execution",
        description=(
            "The analyzed file contains obfuscated JavaScript execution "
            "patterns (eval/atob/String.fromCharCode)."
        ),
        predicate=lambda e: _yara_rule_matched(
            e, "Suspicious_JavaScript_Obfuscation"
        ),
    ),
    MitreRule(
        technique_id="T1588.001",
        technique_name="Obtain Capabilities: Malware",
        tactic="Resource Development",
        description=(
            "The analyzed file's hash has a confirmed malicious "
            "reputation with one or more threat intelligence sources."
        ),
        predicate=_file_reputation_malicious,
    ),
    MitreRule(
        technique_id="T1090",
        technique_name="Proxy",
        tactic="Command and Control",
        description=(
            "The analyzed IP address has a meaningful abuse/malicious "
            "reputation, consistent with use as C2 or relay "
            "infrastructure."
        ),
        predicate=_ip_reputation_malicious,
    ),
    MitreRule(
        technique_id="T1583.001",
        technique_name="Acquire Infrastructure: Domains",
        tactic="Resource Development",
        description=(
            "The analyzed domain has a confirmed malicious reputation, "
            "consistent with attacker-controlled infrastructure."
        ),
        predicate=_domain_reputation_malicious,
    ),
    MitreRule(
        technique_id="T1566.002",
        technique_name="Phishing: Spearphishing Link",
        tactic="Initial Access",
        description=(
            "The analyzed URL is flagged malicious by threat "
            "intelligence sources, consistent with use in a phishing "
            "campaign."
        ),
        predicate=_url_reputation_malicious,
    ),
    MitreRule(
        technique_id="T1589.001",
        technique_name="Gather Victim Identity Information: Credentials",
        tactic="Reconnaissance",
        description=(
            "The analyzed email address appears in known data breaches, "
            "indicating exposed credentials available to attackers."
        ),
        predicate=_breach_found,
    ),
    MitreRule(
        technique_id="T1593.003",
        technique_name="Search Open Websites/Domains: Social Media",
        tactic="Reconnaissance",
        description=(
            "The analyzed username was found registered across multiple "
            "public platforms, giving an attacker a broad social "
            "engineering / OSINT profile of the target."
        ),
        predicate=_username_footprint_found,
    ),
]


def map_mitre_attack(
    evidence_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Evaluates every deterministic rule against the flattened list of
    InvestigationResult-shaped evidence dicts
    (`{"investigation_type", "source", "status", "data"}`), returning one
    entry per matched technique with every triggering source attached as
    evidence. Order is stable (rule table order) and de-duplicated by
    technique_id.
    """

    mapped: dict[str, dict[str, Any]] = {}

    for rule in _MITRE_RULES:

        matching_sources = [
            f"{e.get('investigation_type')}:{e.get('source')}"
            for e in evidence_items
            if rule.predicate(e)
        ]

        if not matching_sources:
            continue

        mapped[rule.technique_id] = {
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "tactic": rule.tactic,
            "description": rule.description,
            "evidence_sources": matching_sources,
        }

    return list(mapped.values())

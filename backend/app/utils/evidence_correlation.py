"""Deterministic, provenance-preserving evidence correlation helpers."""
from dataclasses import dataclass
from urllib.parse import urlparse
import ipaddress

@dataclass(frozen=True)
class InvestigationRef:
    investigation_id: str
    target: str
    investigation_type: str


def normalized_entities(target: str, investigation_type: str = "") -> list[dict]:
    raw = target.strip()
    low = raw.lower()
    entities: list[dict] = []
    def add(kind: str, value: str, relationship: str = "target"):
        item={"entity_type":kind,"value":value.lower(),"relationship":relationship,"confidence":1.0,"provenance":"investigation_target"}
        if item not in entities: entities.append(item)
    if "@" in low:
        local, domain = low.rsplit("@",1); add("email", low); add("domain",domain,"email_domain")
        return entities
    try:
        ipaddress.ip_address(low); add("ip",low); return entities
    except ValueError: pass
    parsed=urlparse(low if "://" in low else "")
    if parsed.hostname:
        add("url",low); add("domain",parsed.hostname,"url_host"); return entities
    if low.startswith(("sha256:","sha1:","md5:")):
        add("file_hash",low.split(":",1)[1]); return entities
    kind = "domain" if "." in low and " " not in low else (investigation_type or "indicator")
    add(kind,low)
    return entities


def normalize_indicator(target: str) -> str:
    entities=normalized_entities(target)
    for item in entities:
        if item["entity_type"] == "domain": return item["value"]
    return entities[0]["value"] if entities else target.strip().lower()


def find_shared_indicators(investigations: list[InvestigationRef]) -> list[dict]:
    groups: dict[tuple[str,str], list[tuple[InvestigationRef,dict]]] = {}
    for inv in investigations:
        for entity in normalized_entities(inv.target, inv.investigation_type):
            groups.setdefault((entity["entity_type"],entity["value"]),[]).append((inv,entity))
    correlated=[]
    for (kind,value), rows in groups.items():
        ids={r[0].investigation_id for r in rows}
        if len(ids)<2: continue
        correlated.append({"shared_indicator":value,"entity_type":kind,"investigation_count":len(ids),"confidence":1.0,
          "provenance":"investigation_targets","investigations":[{"investigation_id":r[0].investigation_id,"investigation_type":r[0].investigation_type,"target":r[0].target,"relationship":r[1]["relationship"]} for r in rows]})
    correlated.sort(key=lambda c:c["investigation_count"],reverse=True)
    return correlated

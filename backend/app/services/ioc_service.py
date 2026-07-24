from sqlalchemy.orm import Session

from backend.app.integrations.ioc.ioc_classifier import classify_ioc
from backend.app.integrations.ioc.ioc_classifier import IOCType
from backend.app.models.investigation import Investigation
from backend.app.models.investigation import InvestigationType
from backend.app.services.domain_service import DomainIntelligenceService
from backend.app.services.email_service import EmailIntelligenceService
from backend.app.services.ip_service import IPIntelligenceService
from backend.app.services.url_service import URLIntelligenceService
from backend.app.services.username_service import UsernameIntelligenceService


class IOCAnalysisService:
    """
    Orchestrates Milestone 5's generic IOC endpoint: classifies a raw
    indicator string (IP / domain / URL / email / username) and
    delegates to whichever existing, specialized service owns that
    indicator type. This class holds NO scoring or integration logic of
    its own - every score/source stays owned by exactly one service,
    so there is nothing to keep in sync when those services evolve.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    async def investigate(
        self,
        *,
        user_id: str,
        indicator: str,
    ) -> tuple[IOCType, Investigation]:

        ioc_type = classify_ioc(indicator)

        if ioc_type == IOCType.IP_ADDRESS:

            investigation = await IPIntelligenceService(self.db).investigate(
                user_id=user_id,
                target=indicator,
            )

        elif ioc_type == IOCType.DOMAIN:

            investigation = await DomainIntelligenceService(self.db).investigate(
                user_id=user_id,
                target=indicator,
                investigation_type=InvestigationType.DOMAIN,
            )

        elif ioc_type == IOCType.URL:

            investigation = await URLIntelligenceService(self.db).investigate(
                user_id=user_id,
                url=indicator,
            )

        elif ioc_type == IOCType.EMAIL:

            investigation = await EmailIntelligenceService(self.db).investigate(
                user_id=user_id,
                email=indicator,
            )

        else:  # IOCType.USERNAME

            investigation = await UsernameIntelligenceService(self.db).investigate(
                user_id=user_id,
                username=indicator,
            )

        return ioc_type, investigation

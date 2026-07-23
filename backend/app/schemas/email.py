from pydantic import BaseModel
from pydantic import EmailStr


class EmailInvestigationRequest(BaseModel):

    email: EmailStr

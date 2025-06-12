from pydantic import BaseModel

class Learner(BaseModel):
    id: str
    name: str
    whatsapp: str
    match_type: str  # "pair" or "group"
    assessment_completed: bool

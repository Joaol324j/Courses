from typing import Optional
from pydantic import BaseModel

class TeacherSchema(BaseModel):
    id: Optional[int] = None
    name: str
    email: str
    phone: str
    specialty: str

    class Config:
        from_attributes = True
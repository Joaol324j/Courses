from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models.enrollment_model import EnrollmentStatus

class EnrollmentBase(BaseModel):
    student_id: int
    course_id: int
    status: Optional[EnrollmentStatus] = EnrollmentStatus.ACTIVE

class EnrollmentCreate(EnrollmentBase):
    pass

class EnrollmentUpdate(EnrollmentBase):
    student_id: Optional[int] = None
    course_id: Optional[int] = None
    status: Optional[EnrollmentStatus] = None

class Enrollment(EnrollmentBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True 
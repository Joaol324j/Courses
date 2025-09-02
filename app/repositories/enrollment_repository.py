from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.enrollment_model import Enrollment
from app.schemas.enrollment_schema import EnrollmentCreate, EnrollmentUpdate

class EnrollmentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self) -> List[Enrollment]:
        return self.db.query(Enrollment).all()

    def get_by_id(self, enrollment_id: int) -> Optional[Enrollment]:
        return self.db.query(Enrollment).filter(Enrollment.id == enrollment_id).first()

    def get_by_student(self, student_id: int) -> List[Enrollment]:
        return self.db.query(Enrollment).filter(Enrollment.student_id == student_id).all()

    def get_by_course(self, course_id: int) -> List[Enrollment]:
        return self.db.query(Enrollment).filter(Enrollment.course_id == course_id).all()

    def create(self, enrollment: EnrollmentCreate) -> Enrollment:
        db_enrollment = Enrollment(**enrollment.model_dump())
        self.db.add(db_enrollment)
        self.db.commit()
        self.db.refresh(db_enrollment)
        return db_enrollment

    def update(self, enrollment_id: int, enrollment: EnrollmentUpdate) -> Optional[Enrollment]:
        db_enrollment = self.get_by_id(enrollment_id)
        if not db_enrollment:
            return None
        
        for key, value in enrollment.model_dump(exclude_unset=True).items():
            setattr(db_enrollment, key, value)
        
        self.db.commit()
        self.db.refresh(db_enrollment)
        return db_enrollment

    def delete(self, enrollment_id: int) -> bool:
        db_enrollment = self.get_by_id(enrollment_id)
        if not db_enrollment:
            return False
        
        self.db.delete(db_enrollment)
        self.db.commit()
        return True 
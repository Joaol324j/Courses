from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.student_model import Student
from app.schemas.student_schema import StudentCreate, StudentUpdate

class StudentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self) -> List[Student]:
        return self.db.query(Student).all()

    def get_by_id(self, student_id: int) -> Optional[Student]:
        return self.db.query(Student).filter(Student.id == student_id).first()

    def get_by_email(self, email: str) -> Optional[Student]:
        return self.db.query(Student).filter(Student.email == email).first()

    def create(self, student: StudentCreate) -> Student:
        db_student = Student(**student.model_dump())
        self.db.add(db_student)
        self.db.commit()
        self.db.refresh(db_student)
        return db_student

    def update(self, student_id: int, student: StudentUpdate) -> Optional[Student]:
        db_student = self.get_by_id(student_id)
        if not db_student:
            return None
        
        for key, value in student.model_dump(exclude_unset=True).items():
            setattr(db_student, key, value)
        
        self.db.commit()
        self.db.refresh(db_student)
        return db_student

    def delete(self, student_id: int) -> bool:
        db_student = self.get_by_id(student_id)
        if not db_student:
            return False
        
        self.db.delete(db_student)
        self.db.commit()
        return True 
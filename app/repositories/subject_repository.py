from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.subject import Subject

class SubjectRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self) -> List[Subject]:
        return self.db.query(Subject).order_by(Subject.name).all()

    def get_by_id(self, subject_id: int) -> Optional[Subject]:
        return self.db.query(Subject).filter(Subject.id == subject_id).first()

    def get_by_code(self, code: str) -> Optional[Subject]:
        return self.db.query(Subject).filter(Subject.code == code).first()

    def create(self, subject: Subject) -> Subject:
        self.db.add(subject)
        self.db.commit()
        self.db.refresh(subject)
        return subject

    def update(self, subject_id: int, subject: Subject) -> Optional[Subject]:
        db_subject = self.get_by_id(subject_id)
        if db_subject:
            for key, value in subject.dict(exclude_unset=True).items():
                setattr(db_subject, key, value)
            self.db.commit()
            self.db.refresh(db_subject)
        return db_subject

    def delete(self, subject_id: int) -> bool:
        db_subject = self.get_by_id(subject_id)
        if db_subject:
            self.db.delete(db_subject)
            self.db.commit()
            return True
        return False 
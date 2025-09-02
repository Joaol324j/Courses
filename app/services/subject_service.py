from typing import List, Optional
from app.repositories.subject_repository import SubjectRepository
from app.schemas.subject import SubjectCreate, SubjectUpdate
from app.models.subject import Subject
from fastapi import HTTPException, status

class SubjectService:
    def __init__(self, subject_repository: SubjectRepository):
        self.subject_repository = subject_repository

    def get_all_subjects(self) -> List[Subject]:
        return self.subject_repository.get_all()

    def get_subject_by_id(self, subject_id: int) -> Optional[Subject]:
        subject = self.subject_repository.get_by_id(subject_id)
        if not subject:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Disciplina não encontrada"
            )
        return subject

    def create_subject(self, subject: SubjectCreate) -> Subject:
        # Verifica se já existe uma disciplina com o mesmo código
        existing_subject = self.subject_repository.get_by_code(subject.code)
        if existing_subject:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Já existe uma disciplina com este código"
            )
        
        db_subject = Subject(**subject.dict())
        return self.subject_repository.create(db_subject)

    def update_subject(self, subject_id: int, subject: SubjectUpdate) -> Optional[Subject]:
        db_subject = self.subject_repository.get_by_id(subject_id)
        if not db_subject:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Disciplina não encontrada"
            )
        
        # Se estiver atualizando o código, verifica se já existe
        if subject.code and subject.code != db_subject.code:
            existing_subject = self.subject_repository.get_by_code(subject.code)
            if existing_subject:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Já existe uma disciplina com este código"
                )
        
        return self.subject_repository.update(subject_id, subject)

    def delete_subject(self, subject_id: int) -> bool:
        db_subject = self.subject_repository.get_by_id(subject_id)
        if not db_subject:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Disciplina não encontrada"
            )
        return self.subject_repository.delete(subject_id) 
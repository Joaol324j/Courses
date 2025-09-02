from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.repositories.student_repository import StudentRepository
from app.schemas.student_schema import StudentCreate, StudentUpdate, StudentResponse

class StudentService:
    def __init__(self, db: Session):
        self.repository = StudentRepository(db)

    def get_all_students(self) -> List[StudentResponse]:
        try:
            students = self.repository.get_all()
            return [StudentResponse.model_validate(student) for student in students]
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao buscar alunos: {str(e)}"
            )

    def get_student_by_id(self, student_id: int) -> StudentResponse:
        student = self.repository.get_by_id(student_id)
        if not student:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Aluno não encontrado"
            )
        return StudentResponse.model_validate(student)

    def create_student(self, student: StudentCreate) -> StudentResponse:
        try:
            if self.repository.get_by_email(student.email):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email já cadastrado"
                )
            
            db_student = self.repository.create(student)
            return StudentResponse.model_validate(db_student)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao criar aluno: {str(e)}"
            )

    def update_student(self, student_id: int, student: StudentUpdate) -> StudentResponse:
        try:
            db_student = self.repository.update(student_id, student)
            if not db_student:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Aluno não encontrado"
                )
            return StudentResponse.model_validate(db_student)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao atualizar aluno: {str(e)}"
            )

    def delete_student(self, student_id: int) -> bool:
        try:
            if not self.repository.delete(student_id):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Aluno não encontrado"
                )
            return True
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao deletar aluno: {str(e)}"
            ) 
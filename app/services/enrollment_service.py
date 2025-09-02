from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.repositories.enrollment_repository import EnrollmentRepository
from app.repositories.student_repository import StudentRepository
from app.repositories.course_repository import CourseRepository
from app.schemas.enrollment_schema import EnrollmentCreate, EnrollmentUpdate, EnrollmentResponse

class EnrollmentService:
    def __init__(self, db: Session):
        self.repository = EnrollmentRepository(db)
        self.student_repository = StudentRepository(db)
        self.course_repository = CourseRepository(db)

    def get_all_enrollments(self) -> List[EnrollmentResponse]:
        try:
            enrollments = self.repository.get_all()
            return [EnrollmentResponse.model_validate(enrollment) for enrollment in enrollments]
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao buscar matrículas: {str(e)}"
            )

    def get_enrollment_by_id(self, enrollment_id: int) -> EnrollmentResponse:
        enrollment = self.repository.get_by_id(enrollment_id)
        if not enrollment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Matrícula não encontrada"
            )
        return EnrollmentResponse.model_validate(enrollment)

    def create_enrollment(self, enrollment: EnrollmentCreate) -> EnrollmentResponse:
        try:
            # Verificar se o aluno existe
            if not self.student_repository.get_by_id(enrollment.student_id):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Aluno não encontrado"
                )

            # Verificar se o curso existe
            if not self.course_repository.get_by_id(enrollment.course_id):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Curso não encontrado"
                )

            # Verificar se o aluno já está matriculado no curso
            existing_enrollments = self.repository.get_by_student(enrollment.student_id)
            for existing in existing_enrollments:
                if existing.course_id == enrollment.course_id:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Aluno já está matriculado neste curso"
                    )
            
            db_enrollment = self.repository.create(enrollment)
            return EnrollmentResponse.model_validate(db_enrollment)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao criar matrícula: {str(e)}"
            )

    def update_enrollment(self, enrollment_id: int, enrollment: EnrollmentUpdate) -> EnrollmentResponse:
        try:
            db_enrollment = self.repository.update(enrollment_id, enrollment)
            if not db_enrollment:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Matrícula não encontrada"
                )
            return EnrollmentResponse.model_validate(db_enrollment)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao atualizar matrícula: {str(e)}"
            )

    def delete_enrollment(self, enrollment_id: int) -> bool:
        try:
            if not self.repository.delete(enrollment_id):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Matrícula não encontrada"
                )
            return True
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao deletar matrícula: {str(e)}"
            ) 
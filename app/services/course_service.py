from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
import logging
from app.repositories.course_repository import CourseRepository
from app.schemas.course_schema import CursoCreate, CursoUpdate, CursoResponse
from app.models.course_model import Curso
from app.utils.validators import validate_curso_data
from app.utils.error_handlers import (
    handle_database_error,
    handle_validation_error,
    handle_not_found_error,
    handle_duplicate_error
)

logger = logging.getLogger(__name__)

class CourseService:
    def __init__(self, repository: CourseRepository):
        self.repository = repository

    def get_all_courses(self) -> List[CursoResponse]:
        try:
            logger.info("Buscando todos os cursos no serviço")
            return self.repository.get_all()
        except Exception as e:
            logger.error(f"Erro ao buscar todos os cursos: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erro ao buscar cursos"
            )

    def get_course_by_id(self, curso_id: int) -> Optional[CursoResponse]:
        try:
            logger.info(f"Buscando curso por ID: {curso_id}")
            curso = self.repository.get_by_id(curso_id)
            if not curso:
                logger.warning(f"Curso não encontrado com ID: {curso_id}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Curso com ID {curso_id} não encontrado"
                )
            return curso
        except HTTPException as he:
            raise he
        except Exception as e:
            logger.error(f"Erro ao buscar curso por ID: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erro ao buscar curso"
            )

    def get_course_by_name(self, name: str) -> Optional[CursoResponse]:
        try:
            logger.info(f"Buscando curso por nome: {name}")
            return self.repository.get_by_name(name)
        except Exception as e:
            logger.error(f"Erro ao buscar curso por nome: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erro ao buscar curso"
            )

    def create_course(self, curso: CursoCreate) -> CursoResponse:
        try:
            logger.info(f"Criando novo curso: {curso.dict()}")
            
            # Verifica se já existe um curso com o mesmo nome
            existing_course = self.get_course_by_name(curso.name)
            if existing_course:
                logger.warning(f"Tentativa de criar curso com nome duplicado: {curso.name}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Já existe um curso com o nome '{curso.name}'"
                )
            
            # Cria o curso
            created_course = self.repository.create(curso)
            logger.info(f"Curso criado com sucesso: {created_course.dict()}")
            return created_course
            
        except HTTPException as he:
            raise he
        except Exception as e:
            logger.error(f"Erro ao criar curso: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erro ao criar curso"
            )

    def update_course(self, curso_id: int, curso_update: CursoUpdate) -> CursoResponse:
        try:
            logger.info(f"Atualizando curso {curso_id} com dados: {curso_update.dict(exclude_unset=True)}")
            
            # Verifica se o curso existe
            existing_course = self.get_course_by_id(curso_id)
            
            # Verifica duplicidade de nome se estiver sendo atualizado
            if curso_update.name and curso_update.name != existing_course.name:
                duplicate_course = self.get_course_by_name(curso_update.name)
                if duplicate_course:
                    logger.warning(f"Tentativa de atualizar curso com nome duplicado: {curso_update.name}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Já existe um curso com o nome '{curso_update.name}'"
                    )
            
            # Atualiza o curso
            updated_course = self.repository.update(curso_id, curso_update)
            logger.info(f"Curso atualizado com sucesso: {updated_course.dict()}")
            return updated_course
            
        except HTTPException as he:
            raise he
        except Exception as e:
            logger.error(f"Erro ao atualizar curso: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erro ao atualizar curso"
            )

    def delete_course(self, curso_id: int) -> None:
        try:
            logger.info(f"Deletando curso: {curso_id}")
            
            # Verifica se o curso existe
            self.get_course_by_id(curso_id)
            
            # Deleta o curso
            self.repository.delete(curso_id)
            logger.info(f"Curso {curso_id} deletado com sucesso")
            
        except HTTPException as he:
            raise he
        except Exception as e:
            logger.error(f"Erro ao deletar curso: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erro ao deletar curso"
            ) 
from typing import List, Optional
from sqlalchemy.orm import Session
import logging
from app.models.course_model import Curso
from app.schemas.course_schema import CursoCreate, CursoUpdate, CursoResponse

logger = logging.getLogger(__name__)

class CourseRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self) -> List[CursoResponse]:
        try:
            logger.info("Buscando todos os cursos no repositório")
            cursos = self.db.query(Curso).all()
            logger.info(f"Encontrados {len(cursos)} cursos")
            return cursos
        except Exception as e:
            logger.error(f"Erro ao buscar todos os cursos: {str(e)}", exc_info=True)
            raise

    def get_by_id(self, curso_id: int) -> Optional[CursoResponse]:
        try:
            logger.info(f"Buscando curso por ID: {curso_id}")
            curso = self.db.query(Curso).filter(Curso.id == curso_id).first()
            if curso:
                logger.info(f"Curso encontrado: {curso.dict()}")
            else:
                logger.warning(f"Curso não encontrado com ID: {curso_id}")
            return curso
        except Exception as e:
            logger.error(f"Erro ao buscar curso por ID: {str(e)}", exc_info=True)
            raise

    def get_by_name(self, name: str) -> Optional[CursoResponse]:
        try:
            logger.info(f"Buscando curso por nome: {name}")
            curso = self.db.query(Curso).filter(Curso.name == name).first()
            if curso:
                logger.info(f"Curso encontrado: {curso.dict()}")
            else:
                logger.info(f"Curso não encontrado com nome: {name}")
            return curso
        except Exception as e:
            logger.error(f"Erro ao buscar curso por nome: {str(e)}", exc_info=True)
            raise

    def create(self, curso: CursoCreate) -> CursoResponse:
        try:
            logger.info(f"Criando novo curso: {curso.dict()}")
            db_curso = Curso(
                name=curso.name,
                description=curso.description,
                time=curso.time
            )
            self.db.add(db_curso)
            self.db.commit()
            self.db.refresh(db_curso)
            logger.info(f"Curso criado com sucesso: {db_curso.dict()}")
            return db_curso
        except Exception as e:
            logger.error(f"Erro ao criar curso: {str(e)}", exc_info=True)
            self.db.rollback()
            raise

    def update(self, curso_id: int, curso_update: CursoUpdate) -> CursoResponse:
        try:
            logger.info(f"Atualizando curso {curso_id} com dados: {curso_update.dict(exclude_unset=True)}")
            db_curso = self.get_by_id(curso_id)
            if not db_curso:
                logger.warning(f"Curso não encontrado para atualização: {curso_id}")
                return None

            update_data = curso_update.dict(exclude_unset=True)
            for field, value in update_data.items():
                setattr(db_curso, field, value)

            self.db.commit()
            self.db.refresh(db_curso)
            logger.info(f"Curso atualizado com sucesso: {db_curso.dict()}")
            return db_curso
        except Exception as e:
            logger.error(f"Erro ao atualizar curso: {str(e)}", exc_info=True)
            self.db.rollback()
            raise

    def delete(self, curso_id: int) -> None:
        try:
            logger.info(f"Deletando curso: {curso_id}")
            db_curso = self.get_by_id(curso_id)
            if not db_curso:
                logger.warning(f"Curso não encontrado para deleção: {curso_id}")
                return

            self.db.delete(db_curso)
            self.db.commit()
            logger.info(f"Curso {curso_id} deletado com sucesso")
        except Exception as e:
            logger.error(f"Erro ao deletar curso: {str(e)}", exc_info=True)
            self.db.rollback()
            raise

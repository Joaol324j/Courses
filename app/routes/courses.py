from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
import logging
from app.database import get_db
from app.schemas.course_schema import CourseCreate, CourseUpdate, Course
from app.routes.auth import get_current_user
from app.models.user_model import User
from app.models.course_model import Curso

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/", response_model=List[Course])
async def get_courses(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        logger.info("Buscando todos os cursos")
        courses = db.query(Curso).all()
        logger.info(f"Encontrados {len(courses)} cursos")
        return courses
    except Exception as e:
        logger.error(f"Erro ao buscar cursos: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao buscar cursos"
        )

@router.post("/", response_model=Course, status_code=status.HTTP_201_CREATED)
async def create_course(
    course: CourseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        logger.info(f"Tentando criar curso: {course.dict()}")
        
        # Verifica se já existe um curso com o mesmo nome
        existing_course = db.query(Curso).filter(Curso.name == course.name).first()
        if existing_course:
            logger.warning(f"Tentativa de criar curso com nome duplicado: {course.name}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Já existe um curso com o nome '{course.name}'"
            )
        
        db_course = Curso(**course.dict())
        db.add(db_course)
        db.commit()
        db.refresh(db_course)
        logger.info(f"Curso criado com sucesso: {db_course.dict()}")
        return db_course
        
    except HTTPException as he:
        logger.error(f"Erro HTTP ao criar curso: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Erro inesperado ao criar curso: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao criar curso"
        )

@router.get("/{course_id}", response_model=Course)
async def get_course(
    course_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        logger.info(f"Buscando curso com ID: {course_id}")
        course = db.query(Curso).filter(Curso.id == course_id).first()
        if not course:
            logger.warning(f"Curso não encontrado com ID: {course_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Curso com ID {course_id} não encontrado"
            )
        logger.info(f"Curso encontrado: {course.dict()}")
        return course
    except HTTPException as he:
        logger.error(f"Erro HTTP ao buscar curso: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Erro inesperado ao buscar curso: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao buscar curso"
        )

@router.put("/{course_id}", response_model=Course)
async def update_course(
    course_id: int,
    course: CourseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        logger.info(f"Tentando atualizar curso {course_id} com dados: {course.dict(exclude_unset=True)}")
        
        # Verifica se o curso existe
        db_course = db.query(Curso).filter(Curso.id == course_id).first()
        if not db_course:
            logger.warning(f"Tentativa de atualizar curso inexistente: {course_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Curso com ID {course_id} não encontrado"
            )
        
        # Verifica duplicidade de nome se estiver sendo atualizado
        if course.name and course.name != db_course.name:
            duplicate_course = db.query(Curso).filter(Curso.name == course.name).first()
            if duplicate_course:
                logger.warning(f"Tentativa de atualizar curso com nome duplicado: {course.name}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Já existe um curso com o nome '{course.name}'"
                )
        
        for key, value in course.dict(exclude_unset=True).items():
            setattr(db_course, key, value)
        
        db.commit()
        db.refresh(db_course)
        logger.info(f"Curso atualizado com sucesso: {db_course.dict()}")
        return db_course
        
    except HTTPException as he:
        logger.error(f"Erro HTTP ao atualizar curso: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Erro inesperado ao atualizar curso: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao atualizar curso"
        )

@router.delete("/{course_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_course(
    course_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        logger.info(f"Tentando deletar curso: {course_id}")
        
        # Verifica se o curso existe
        db_course = db.query(Curso).filter(Curso.id == course_id).first()
        if not db_course:
            logger.warning(f"Tentativa de deletar curso inexistente: {course_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Curso com ID {course_id} não encontrado"
            )
        
        db.delete(db_course)
        db.commit()
        logger.info(f"Curso {course_id} deletado com sucesso")
        return None
        
    except HTTPException as he:
        logger.error(f"Erro HTTP ao deletar curso: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Erro inesperado ao deletar curso: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao deletar curso"
        )

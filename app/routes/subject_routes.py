from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.schemas.subject import Subject, SubjectCreate, SubjectUpdate
from app.services.subject_service import SubjectService
from app.repositories.subject_repository import SubjectRepository

router = APIRouter()

@router.get("/subjects", response_model=List[Subject])
async def get_subjects(db: Session = Depends(get_db)):
    """
    Retorna todas as disciplinas cadastradas.
    """
    try:
        subject_repository = SubjectRepository(db)
        subject_service = SubjectService(subject_repository)
        return subject_service.get_all_subjects()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/subjects", response_model=Subject, status_code=status.HTTP_201_CREATED)
async def create_subject(subject: SubjectCreate, db: Session = Depends(get_db)):
    """
    Cria uma nova disciplina.
    """
    try:
        subject_repository = SubjectRepository(db)
        subject_service = SubjectService(subject_repository)
        return subject_service.create_subject(subject)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/subjects/{subject_id}", response_model=Subject)
async def get_subject(subject_id: int, db: Session = Depends(get_db)):
    """
    Retorna uma disciplina específica pelo ID.
    """
    try:
        subject_repository = SubjectRepository(db)
        subject_service = SubjectService(subject_repository)
        return subject_service.get_subject_by_id(subject_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.put("/subjects/{subject_id}", response_model=Subject)
async def update_subject(subject_id: int, subject: SubjectUpdate, db: Session = Depends(get_db)):
    """
    Atualiza uma disciplina existente.
    """
    try:
        subject_repository = SubjectRepository(db)
        subject_service = SubjectService(subject_repository)
        return subject_service.update_subject(subject_id, subject)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.delete("/subjects/{subject_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subject(subject_id: int, db: Session = Depends(get_db)):
    """
    Exclui uma disciplina.
    """
    try:
        subject_repository = SubjectRepository(db)
        subject_service = SubjectService(subject_repository)
        subject_service.delete_subject(subject_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        ) 
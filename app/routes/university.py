from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.repositories.university_repository import UniversityRepository
from app.schemas.university import University, UniversityCreate, UniversityUpdate

router = APIRouter(
    prefix="/universities",
    tags=["universities"]
)

@router.post("/", response_model=University)
def create_university(university: UniversityCreate, db: Session = Depends(get_db)):
    repo = UniversityRepository(db)
    return repo.create(university)

@router.get("/", response_model=List[University])
def get_universities(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    repo = UniversityRepository(db)
    return repo.get_all(skip=skip, limit=limit)

@router.get("/{university_id}", response_model=University)
def get_university(university_id: int, db: Session = Depends(get_db)):
    repo = UniversityRepository(db)
    university = repo.get_by_id(university_id)
    if not university:
        raise HTTPException(status_code=404, detail="Universidade não encontrada")
    return university

@router.put("/{university_id}", response_model=University)
def update_university(university_id: int, university: UniversityUpdate, db: Session = Depends(get_db)):
    repo = UniversityRepository(db)
    updated_university = repo.update(university_id, university)
    if not updated_university:
        raise HTTPException(status_code=404, detail="Universidade não encontrada")
    return updated_university

@router.delete("/{university_id}")
def delete_university(university_id: int, db: Session = Depends(get_db)):
    repo = UniversityRepository(db)
    if not repo.delete(university_id):
        raise HTTPException(status_code=404, detail="Universidade não encontrada")
    return {"message": "Universidade excluída com sucesso"} 
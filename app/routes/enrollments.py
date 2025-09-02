from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.enrollment_model import Enrollment
from app.routes.auth import get_current_user
from app.models.user_model import User
from app.schemas.enrollment_schema import EnrollmentCreate, EnrollmentUpdate, Enrollment

router = APIRouter()

@router.get("/", response_model=List[Enrollment])
async def get_enrollments(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    enrollments = db.query(Enrollment).all()
    return enrollments

@router.post("/", response_model=Enrollment)
async def create_enrollment(
    enrollment: EnrollmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_enrollment = Enrollment(**enrollment.dict())
    db.add(db_enrollment)
    db.commit()
    db.refresh(db_enrollment)
    return db_enrollment

@router.get("/{enrollment_id}", response_model=Enrollment)
async def get_enrollment(
    enrollment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    enrollment = db.query(Enrollment).filter(Enrollment.id == enrollment_id).first()
    if enrollment is None:
        raise HTTPException(status_code=404, detail="Matrícula não encontrada")
    return enrollment

@router.put("/{enrollment_id}", response_model=Enrollment)
async def update_enrollment(
    enrollment_id: int,
    enrollment: EnrollmentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_enrollment = db.query(Enrollment).filter(Enrollment.id == enrollment_id).first()
    if db_enrollment is None:
        raise HTTPException(status_code=404, detail="Matrícula não encontrada")
    
    for key, value in enrollment.dict(exclude_unset=True).items():
        setattr(db_enrollment, key, value)
    
    db.commit()
    db.refresh(db_enrollment)
    return db_enrollment

@router.delete("/{enrollment_id}")
async def delete_enrollment(
    enrollment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_enrollment = db.query(Enrollment).filter(Enrollment.id == enrollment_id).first()
    if db_enrollment is None:
        raise HTTPException(status_code=404, detail="Matrícula não encontrada")
    
    db.delete(db_enrollment)
    db.commit()
    return {"message": "Matrícula deletada com sucesso"} 
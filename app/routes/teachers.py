from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from fastapi.templating import Jinja2Templates
from app.schemas.teacher_schema import TeacherSchema
from app.database import get_db
from app.models.teacher_model import Teacher

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/professores")
def get_teachers_page(request: Request):
    return templates.TemplateResponse("teachers.html", {"request": request})

@router.get("/professores/")
def get_teachers(db: Session = Depends(get_db)):
    teachers = db.query(Teacher).all()
    return teachers

@router.get("/professores/{teacher_id}")
def get_teacher_by_id(teacher_id: int, db: Session = Depends(get_db)):
    teacher = db.query(Teacher).filter(Teacher.id == teacher_id).first()
    if not teacher:
        raise HTTPException(status_code=404, detail="Professor não encontrado")
    return teacher

@router.post("/professores/")
def create_teacher(name: str, email: str, phone: str = None, specialty: str = None, db: Session = Depends(get_db)):
    try:
        teacher = Teacher(
            name=name,
            email=email,
            phone=phone,
            specialty=specialty
        )
        db.add(teacher)
        db.commit()
        db.refresh(teacher)
        return teacher
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/professores/{teacher_id}")
def update_teacher(teacher_id: int, name: str, email: str, phone: str = None, specialty: str = None, db: Session = Depends(get_db)):
    teacher = db.query(Teacher).filter(Teacher.id == teacher_id).first()
    if not teacher:
        raise HTTPException(status_code=404, detail="Professor não encontrado")
    
    teacher.name = name
    teacher.email = email
    teacher.phone = phone
    teacher.specialty = specialty
    
    try:
        db.commit()
        db.refresh(teacher)
        return teacher
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/professores/{teacher_id}")
def delete_teacher(teacher_id: int, db: Session = Depends(get_db)):
    teacher = db.query(Teacher).filter(Teacher.id == teacher_id).first()
    if not teacher:
        raise HTTPException(status_code=404, detail="Professor não encontrado")
    
    try:
        db.delete(teacher)
        db.commit()
        return {"message": "Professor deletado com sucesso"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
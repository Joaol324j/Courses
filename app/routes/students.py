from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from fastapi.templating import Jinja2Templates

from app.database import get_db
from app.models.student_model import Student as StudentModel
from app.schemas.student_schema import StudentCreate, StudentUpdate, Student

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/alunos/", response_model=List[Student])
def get_students(db: Session = Depends(get_db)):
    students = db.query(StudentModel).all()
    return students

@router.get("/alunos/{student_id}", response_model=Student)
def get_student_by_id(student_id: int, db: Session = Depends(get_db)):
    student = db.query(StudentModel).filter(StudentModel.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Aluno não encontrado")
    return student

@router.post("/alunos/", response_model=Student)
def create_student(student: StudentCreate, db: Session = Depends(get_db)):
    db_student = StudentModel(
        name=student.name,
        email=student.email,
        phone=student.phone
    )
    db.add(db_student)
    db.commit()
    db.refresh(db_student)
    return db_student

@router.put("/alunos/{student_id}", response_model=Student)
def update_student(student_id: int, student: StudentUpdate, db: Session = Depends(get_db)):
    db_student = db.query(StudentModel).filter(StudentModel.id == student_id).first()
    if not db_student:
        raise HTTPException(status_code=404, detail="Aluno não encontrado")
    
    db_student.name = student.name
    db_student.email = student.email
    db_student.phone = student.phone
    
    db.commit()
    db.refresh(db_student)
    return db_student

@router.delete("/alunos/{student_id}")
def delete_student(student_id: int, db: Session = Depends(get_db)):
    student = db.query(StudentModel).filter(StudentModel.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Aluno não encontrado")
    
    db.delete(student)
    db.commit()
    return {"message": "Aluno deletado com sucesso"}
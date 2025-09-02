from typing import Optional
from pydantic import BaseModel, Field, validator
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class CourseBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Nome do curso")
    description: str = Field(..., min_length=1, max_length=500, description="Descrição do curso")
    time: int = Field(..., ge=1, description="Duração do curso em horas")

    @validator('time')
    def validate_time(cls, v):
        logger.info(f"Validando duração do curso: {v}")
        if not isinstance(v, int):
            try:
                v = int(v)
            except (ValueError, TypeError):
                raise ValueError("A duração deve ser um número inteiro")
        if v < 1:
            raise ValueError("A duração deve ser maior que zero")
        return v

    @validator('name')
    def validate_name(cls, v):
        logger.info(f"Validando nome do curso: {v}")
        if not v or not v.strip():
            raise ValueError("O nome do curso não pode estar vazio")
        return v.strip()

    @validator('description')
    def validate_description(cls, v):
        logger.info(f"Validando descrição do curso: {v}")
        if not v or not v.strip():
            raise ValueError("A descrição do curso não pode estar vazia")
        return v.strip()

class CourseCreate(CourseBase):
    class Config:
        json_schema_extra = {
            "example": {
                "name": "Curso de Python",
                "description": "Aprenda Python do zero ao avançado",
                "time": 40
            }
        }

class CourseUpdate(CourseBase):
    """Schema para atualização de curso."""
    name: Optional[str] = None
    description: Optional[str] = None
    time: Optional[int] = None

    @validator('time')
    def validate_time(cls, v):
        if v is not None:
            logger.info(f"Validando duração do curso na atualização: {v}")
            if not isinstance(v, int):
                try:
                    v = int(v)
                except (ValueError, TypeError):
                    raise ValueError("A duração deve ser um número inteiro")
            if v < 1:
                raise ValueError("A duração deve ser maior que zero")
        return v

    @validator('name')
    def validate_name(cls, v):
        if v is not None:
            logger.info(f"Validando nome do curso na atualização: {v}")
            if not v.strip():
                raise ValueError("O nome do curso não pode estar vazio")
            return v.strip()
        return v

    @validator('description')
    def validate_description(cls, v):
        if v is not None:
            logger.info(f"Validando descrição do curso na atualização: {v}")
            if not v.strip():
                raise ValueError("A descrição do curso não pode estar vazia")
            return v.strip()
        return v

class Course(CourseBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
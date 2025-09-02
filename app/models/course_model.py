from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.models.base import Base
import logging

logger = logging.getLogger(__name__)

class Curso(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    time = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relacionamento com matrículas
    enrollments = relationship("Enrollment", back_populates="course")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        logger.info(f"Inicializando novo curso: {self.dict()}")

    def dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "time": self.time,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

    def __repr__(self):
        return f"<Curso {self.name}>"
from app.models.course_model import Curso
from app.repositories.course_repository import CourseRepository
from app.schemas.course_schema import CursoCreate, CursoUpdate

class CourseService:
    def __init__(self, course_repository: CourseRepository):
        self.course_repository = course_repository

    def create_course(self, course_data: CursoCreate) -> Curso:
        """Cria um novo curso."""
        return self.course_repository.create_course(
            name=course_data.name,
            description=course_data.description,
            time=course_data.time
        )

    def get_course(self, course_id: int) -> Curso:
        """Busca um curso pelo ID."""
        return self.course_repository.get_by_id(course_id)

    def get_all_courses(self, skip: int = 0, limit: int = 10) -> list[Curso]:
        """Retorna uma lista de cursos com paginação."""
        return self.course_repository.get_all(skip, limit)

    def update_course(self, course_id: int, course_data: CursoUpdate) -> Curso:
        """Atualiza um curso existente."""
        return self.course_repository.update_course(
            course_id=course_id,
            name=course_data.name,
            description=course_data.description,
            time=course_data.time
        )

    def delete_course(self, course_id: int) -> None:
        """Deleta um curso."""
        return self.course_repository.delete_course(course_id)
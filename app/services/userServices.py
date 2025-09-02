# app/services/user_service.py
from app.repositories.user_repository import UserRepository
from app.schemas.user_schema import UserCreate
from app.core.security import get_password_hash, verify_password

class UserService:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    def register_user(self, user_data: UserCreate) -> User:
        """Registra um novo usuário."""
        hashed_password = get_password_hash(user_data.password)
        return self.user_repository.create_user(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password
        )

    def authenticate_user(self, username: str, password: str) -> User:
        """Autentica um usuário."""
        user = self.user_repository.get_by_username(username)
        if not user or not verify_password(password, user.hashed_password):
            return None  # Falha na autenticação
        return user  # Autenticação bem-sucedida
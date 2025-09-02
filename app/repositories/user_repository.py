# app/repositories/user_repository.py
from sqlalchemy.orm import Session
from app.models.user_model import User

class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_username(self, username: str) -> User:
        """Busca um usuário pelo nome de usuário."""
        return self.db.query(User).filter(User.username == username).first()

    def create_user(self, username: str, email: str, hashed_password: str) -> User:
        """Cria um novo usuário no banco de dados."""
        db_user = User(username=username, email=email, hashed_password=hashed_password)
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        return db_user
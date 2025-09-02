from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import pytest

from app.main import app
from app.database import get_db
from app.models.base import Base
from app.routes.auth import get_current_user
from app.models.user_model import User
from app.schemas.user_schema import UserResponse
from app.core.security import create_access_token, get_password_hash

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(name="session")
def session_fixture():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(name="client")
def client_fixture(session):
    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()

@pytest.fixture(name="test_user")
def test_user_fixture(session: TestingSessionLocal):
    hashed_password = get_password_hash("testpassword")
    user = User(username="testuser", email="test@example.com", hashed_password=hashed_password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@pytest.fixture(name="auth_token")
def auth_token_fixture(test_user: User):
    access_token = create_access_token(data={"sub": test_user.username})
    return f"Bearer {access_token}"

@pytest.fixture(name="current_user_override")
def current_user_override_fixture(test_user: User):
    app.dependency_overrides[get_current_user] = lambda: test_user
    yield
    app.dependency_overrides.clear()

def test_create_course(client: TestClient, current_user_override):
    response = client.post(
        "/cursos/",
        json={"name": "Curso de Teste", "description": "Descrição do Curso de Teste", "time": 10}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Curso de Teste"
    assert data["description"] == "Descrição do Curso de Teste"
    assert data["time"] == 10
    assert "id" in data

def test_get_courses(client: TestClient, current_user_override):
    client.post(
        "/cursos/",
        json={"name": "Curso de Teste 2", "description": "Outra descrição", "time": 20}
    )

    response = client.get(
        "/cursos/", 
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert any(course["name"] == "Curso de Teste 2" for course in data)

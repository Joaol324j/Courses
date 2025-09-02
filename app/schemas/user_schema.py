from typing import Optional
from pydantic import BaseModel, EmailStr

# Padrão de criação de usuário
class UserCreate(BaseModel):
    """Schema para criação de usuário."""
    username: str
    email: EmailStr
    password: str

    class Config:
        orm_mode = True  # Configuração para compatibilidade com ORM

# Padrão de login de usuário
class UserLogin(BaseModel):
    """Schema para login de usuário."""
    username: str
    password: str

# Resposta do usuário (quando o usuário é retornado da API)
class UserResponse(BaseModel):
    """Schema para resposta de usuário."""
    id: int
    username: str
    email: EmailStr
    profile_image: Optional[str] = None

    class Config:
        orm_mode = True  # Faz com que o Pydantic converta modelos ORM em modelos Pydantic

# Token de autenticação JWT
class Token(BaseModel):
    """Schema para token JWT."""
    access_token: str
    token_type: str

# Dados do token (para ser usado quando decodificado)
class TokenData(BaseModel):
    """Schema para dados do token JWT."""
    username: Optional[str] = None

# UserSchema será a base para respostas padrão
class UserSchema(UserResponse):
    """Schema genérico de usuário, que pode ser utilizado em várias partes da API."""
    pass

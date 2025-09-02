import os
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from app.config.settings import settings
from app.utils.exceptions import UnauthorizedException
from app.utils.constants import ERROR_MESSAGES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se a senha em texto plano corresponde à senha hash.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Gera o hash de uma senha.
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Cria um token de acesso JWT.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    """
    Verifica e decodifica um token JWT.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def generate_secret_key() -> str:
    """
    Gera uma chave secreta segura.
    """
    return secrets.token_urlsafe(32)

def hash_file(file_path: str) -> str:
    """
    Gera um hash SHA-256 de um arquivo.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def sanitize_filename(filename: str) -> str:
    """
    Sanitiza um nome de arquivo para evitar injeção de diretório.
    """
    # Remove caracteres perigosos
    filename = "".join(c for c in filename if c.isalnum() or c in ('-', '_', '.'))
    
    # Remove extensões perigosas
    dangerous_extensions = {'.exe', '.dll', '.sh', '.bat', '.cmd'}
    if os.path.splitext(filename)[1].lower() in dangerous_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de arquivo não permitido"
        )
    
    return filename

def validate_file_size(file_size: int, max_size_mb: int = 10) -> bool:
    """
    Valida o tamanho de um arquivo.
    """
    max_size_bytes = max_size_mb * 1024 * 1024
    return file_size <= max_size_bytes

def generate_csrf_token() -> str:
    """
    Gera um token CSRF.
    """
    return secrets.token_urlsafe(32)

def verify_csrf_token(token: str, stored_token: str) -> bool:
    """
    Verifica um token CSRF.
    """
    return secrets.compare_digest(token, stored_token)

def encrypt_data(data: str) -> str:
    """
    Criptografa dados sensíveis.
    """
    return pwd_context.encrypt(data)

def decrypt_data(encrypted_data: str) -> str:
    """
    Descriptografa dados sensíveis.
    """
    return pwd_context.decrypt(encrypted_data) 
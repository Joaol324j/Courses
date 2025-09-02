from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.models.user_model import User
from app.core.security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    token_data = decode_access_token(token) 
    if not token_data or "sub" not in token_data:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

    username = token_data["sub"]  

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")

    return user


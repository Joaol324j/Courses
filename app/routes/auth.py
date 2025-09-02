from pyexpat import model
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user_model import User
from app.models.course_model import Curso
from app.core.security import verify_password, create_access_token, create_password_reset_token, get_password_hash, jwt, SECRET_KEY, ALGORITHM, JWTError
from app.schemas.user_schema import Token, UserCreate, UserResponse
from app.services.auth_service import AuthService
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import timedelta
from app.config.settings import settings

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

@router.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    service = AuthService(db)
    return service.register_user(user)

@router.post("/token")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    auth_service = AuthService(db)
    user = auth_service.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth_service.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    auth_service = AuthService(db)
    payload = auth_service.verify_token(token)
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = auth_service.get_user_by_username(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def send_password_reset_email(email: str, token: str):
    sender_email = settings.SMTP_USERNAME
    receiver_email = email
    subject = "Recuperação de Senha"
    body = f"Use o seguinte link para redefinir sua senha: http://localhost:8000/reset-password?token={token}"

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(sender_email, receiver_email, msg.as_string())
    except Exception as e:
        raise HTTPException(status_code=500, detail="Erro ao enviar email de recuperação.")

@router.post("/password-recovery")
def password_recovery(email: str, db: Session = Depends(get_db)):
    user = db.query(model.UserModel).filter(model.UserModel.email == email).first()  # Corrigido: 'models.UserModel'
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    token = create_password_reset_token(data={"sub": email})
    send_password_reset_email(email, token)
    return {"message": "Email de recuperação enviado."}

@router.post("/reset-password")
def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Token inválido.")
        
        user = db.query(model.UserModel).filter(model.UserModel.email == email).first()  # Corrigido: 'models.UserModel'
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")
        
        user.hashed_password = get_password_hash(new_password)
        db.commit()
        db.refresh(user)
        return {"message": "Senha redefinida com sucesso."}
    except JWTError:
        raise HTTPException(status_code=400, detail="Token inválido ou expirado.")

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.exceptions import RequestValidationError
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import logging
import os
from app.routes import students
from app.routes import courses, auth, students, enrollments
from app.database import get_db, init_db
from app.config.logging_config import setup_logging
from app.config.settings import settings
from app.models.course_model import Curso
from app.routes import teachers
from app.routes import subject


# Configuração do logging
logger = setup_logging()

# Cria a aplicação FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG
)

# Configuração do CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Monta os arquivos estáticos
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Inclui as rotas
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(courses.router, prefix="/cursos", tags=["cursos"])
app.include_router(students.router, tags=["alunos"])
app.include_router(teachers.router, tags=["professores"])
app.include_router(enrollments.router, prefix="/matriculas", tags=["matriculas"])
app.include_router(subject.router, tags=["disciplinas"])

@app.on_event("startup")
async def startup_event():
    """
    Evento executado quando a aplicação inicia.
    """
    try:
        logger.info(f"Iniciando aplicação {settings.APP_NAME} v{settings.APP_VERSION}")
        # Inicializa o banco de dados
        init_db()
        logger.info("Aplicação iniciada com sucesso")
    except Exception as e:
        logger.error(f"Erro ao iniciar aplicação: {str(e)}", exc_info=True)
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """
    Evento executado quando a aplicação é encerrada.
    """
    try:
        logger.info("Encerrando aplicação")
        logger.info("Aplicação encerrada com sucesso")
    except Exception as e:
        logger.error(f"Erro ao encerrar aplicação: {str(e)}", exc_info=True)
        raise

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Manipulador de exceções para erros de validação.
    """
    logger.error(f"Erro de validação: {str(exc)}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Manipulador de exceções para erros gerais.
    """
    logger.error(f"Erro não tratado: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Erro interno do servidor"}
    )

@app.get("/")
async def root():
    """
    Rota raiz que redireciona para a página de login.
    """
    return RedirectResponse(url="/login")

@app.get("/login")
async def read_login(request: Request, db: Session = Depends(get_db)):
    """
    Rota para exibir a página de login.
    """
    try:
        return templates.TemplateResponse("login.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar página de login: {str(e)}")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Erro ao carregar página de login."}
        )

@app.get("/register")
async def read_register(request: Request):
    """
    Rota para exibir a página de registro.
    """
    try:
        return templates.TemplateResponse("register.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar página de registro: {str(e)}")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Erro ao carregar página de registro."}
        )

@app.get("/password-recovery")
async def read_password_recovery(request: Request):
    """
    Rota para exibir a página de recuperação de senha.
    """
    try:
        return templates.TemplateResponse("password_recovery.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar página de recuperação de senha: {str(e)}")
        return templates.TemplateResponse(
            "password_recovery.html",
            {"request": request, "error": "Erro ao carregar página de recuperação de senha."}
        )

@app.get("/reset-password")
async def read_reset_password(request: Request):
    """
    Rota para exibir a página de redefinição de senha.
    """
    try:
        return templates.TemplateResponse("reset_password.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar página de redefinição de senha: {str(e)}")
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "error": "Erro ao carregar página de redefinição de senha."}
        )

@app.get("/home")
async def read_dashboard(request: Request, db: Session = Depends(get_db)):
    """
    Rota para exibir o dashboard após o login.
    """
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar página home: {str(e)}")
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": "Erro ao carregar home."}
        )

@app.get("/cursos")
async def read_courses(request: Request, db: Session = Depends(get_db)):
    """
    Rota para exibir a página de cursos.
    """
    try:
        return templates.TemplateResponse("courses.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar cursos: {str(e)}")
        return templates.TemplateResponse(
            "courses.html",
            {"request": request, "error": "Erro ao carregar cursos."}
        )
    
    # ... existing code ...
@app.get("/alunos")
async def read_students(request: Request, db: Session = Depends(get_db)):
    """
    Rota para exibir a página de gerenciamento de alunos.
    """
    try:
        return templates.TemplateResponse("students.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar página de alunos: {str(e)}")
        return templates.TemplateResponse(
            "students.html",
            {"request": request, "error": "Erro ao carregar página de alunos."}
        )

@app.get("/professores")
async def read_teachers(request: Request, db: Session = Depends(get_db)):
    """
    Rota para exibir a página de gerenciamento de professores.
    """
    try:
        return templates.TemplateResponse("teachers.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar página de professores: {str(e)}")
        return templates.TemplateResponse(
            "teachers.html",
            {"request": request, "error": "Erro ao carregar página de professores."}
        )

@app.get("/matriculas", response_class=HTMLResponse)
async def enrollments(request: Request):
    return templates.TemplateResponse("enrollments.html", {"request": request})

@app.get("/disciplinas")
async def read_subjects(request: Request, db: Session = Depends(get_db)):
    """
    Rota para exibir a página de gerenciamento de disciplinas.
    """
    try:
        return templates.TemplateResponse("subjects.html", {"request": request})
    except Exception as e:
        logger.error(f"Erro ao renderizar página de disciplinas: {str(e)}")
        return templates.TemplateResponse(
            "subjects.html",
            {"request": request, "error": "Erro ao carregar página de disciplinas."}
        )
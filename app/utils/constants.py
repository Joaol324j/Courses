from enum import Enum

class UserRole(str, Enum):
    """
    Papéis de usuário disponíveis no sistema.
    """
    ADMIN = "admin"
    TEACHER = "teacher"
    STUDENT = "student"

class CourseStatus(str, Enum):
    """
    Status possíveis para um curso.
    """
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"
    CANCELLED = "cancelled"

class EnrollmentStatus(str, Enum):
    """
    Status possíveis para uma matrícula.
    """
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    SUSPENDED = "suspended"

# Mensagens de erro comuns
ERROR_MESSAGES = {
    "not_found": "Recurso não encontrado",
    "unauthorized": "Não autorizado",
    "forbidden": "Acesso negado",
    "validation_error": "Erro de validação",
    "database_error": "Erro no banco de dados",
    "duplicate_entry": "Registro já existe",
    "invalid_credentials": "Credenciais inválidas",
}

# Configurações de paginação
PAGINATION = {
    "default_limit": 100,
    "max_limit": 1000,
    "min_limit": 1,
}

# Configurações de cache
CACHE = {
    "default_ttl": 300,  # 5 minutos
    "max_ttl": 3600,     # 1 hora
}

# Configurações de arquivo
FILE = {
    "max_size_mb": 10,
    "allowed_extensions": {
        ".pdf", ".doc", ".docx", ".txt", ".jpg", ".jpeg", ".png", ".gif"
    },
    "dangerous_extensions": {
        ".exe", ".dll", ".sh", ".bat", ".cmd"
    }
}

# Configurações de segurança
SECURITY = {
    "password_min_length": 8,
    "token_expire_minutes": 30,
    "refresh_token_expire_days": 7,
    "max_login_attempts": 5,
    "lockout_minutes": 30
}

# Configurações de email
EMAIL = {
    "from_name": "Sistema de Gerenciamento de Cursos",
    "from_email": "noreply@example.com",
    "templates_dir": "templates/email"
}

# Configurações de logging
LOGGING = {
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "date_format": "%Y-%m-%d %H:%M:%S",
    "file_max_bytes": 10 * 1024 * 1024,  # 10MB
    "file_backup_count": 5
}

# Configurações de API
API = {
    "title": "API de Gerenciamento de Cursos",
    "version": "1.0.0",
    "description": "API para gerenciamento de cursos e matrículas",
    "docs_url": "/docs",
    "redoc_url": "/redoc",
    "openapi_url": "/openapi.json"
}

# Configurações de banco de dados
DATABASE = {
    "pool_size": 5,
    "max_overflow": 10,
    "pool_timeout": 30,
    "pool_recycle": 1800
} 
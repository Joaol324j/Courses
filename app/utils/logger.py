import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from app.config.settings import settings

def setup_logger(name: str) -> logging.Logger:
    """
    Configura um logger com handlers para arquivo e console.
    """
    logger = logging.getLogger(name)
    logger.setLevel(settings.LOG_LEVEL)
    
    # Formato do log
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler para arquivo
    log_dir = Path(settings.LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        log_dir / f"{name}.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(settings.LOG_LEVEL)
    file_handler.setFormatter(formatter)
    
    # Handler para console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(settings.LOG_LEVEL)
    console_handler.setFormatter(formatter)
    
    # Adiciona handlers ao logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """
    Retorna um logger já configurado.
    """
    return logging.getLogger(name)

# Loggers específicos
api_logger = setup_logger('api')
db_logger = setup_logger('database')
auth_logger = setup_logger('auth')
cache_logger = setup_logger('cache')
error_logger = setup_logger('error')

def log_request(request, response, duration: float):
    """
    Registra informações sobre uma requisição HTTP.
    """
    api_logger.info(
        f"Request: {request.method} {request.url.path} "
        f"Status: {response.status_code} "
        f"Duration: {duration:.2f}s"
    )

def log_error(error: Exception, context: str = None):
    """
    Registra um erro com contexto.
    """
    error_logger.error(
        f"Error: {str(error)} "
        f"Context: {context or 'No context provided'}"
    )

def log_db_operation(operation: str, table: str, duration: float):
    """
    Registra uma operação no banco de dados.
    """
    db_logger.info(
        f"DB Operation: {operation} "
        f"Table: {table} "
        f"Duration: {duration:.2f}s"
    )

def log_auth_event(event: str, user_id: str = None):
    """
    Registra um evento de autenticação.
    """
    auth_logger.info(
        f"Auth Event: {event} "
        f"User ID: {user_id or 'No user'}"
    )

def log_cache_event(event: str, key: str = None):
    """
    Registra um evento de cache.
    """
    cache_logger.info(
        f"Cache Event: {event} "
        f"Key: {key or 'No key'}"
    ) 
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from app.config.settings import settings

def setup_logging():
    # Configura o logger raiz
    logger = logging.getLogger()
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
        log_dir / "app.log",
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
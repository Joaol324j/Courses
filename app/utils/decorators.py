import functools
import time
import logging
from typing import Any, Callable
from fastapi import HTTPException, status
from app.utils.constants import ERROR_MESSAGES

logger = logging.getLogger(__name__)

def require_role(role: str):
    """
    Decorator para verificar se o usuário tem a role necessária.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get("current_user")
            if not user or user.role != role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=ERROR_MESSAGES["forbidden"]
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def log_execution_time(func: Callable) -> Callable:
    """
    Decorator para registrar o tempo de execução de uma função.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(
                f"Função {func.__name__} executada em {execution_time:.2f} segundos"
            )
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(
                f"Erro na função {func.__name__} após {execution_time:.2f} segundos: {str(e)}"
            )
            raise
    return wrapper

def handle_errors(func: Callable) -> Callable:
    """
    Decorator para tratamento padronizado de erros.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        try:
            return await func(*args, **kwargs)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro não tratado em {func.__name__}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=ERROR_MESSAGES["database_error"]
            )
    return wrapper

def validate_input(schema: Any):
    """
    Decorator para validar dados de entrada usando um schema Pydantic.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                validated_data = schema(**kwargs)
                return await func(*args, **validated_data.dict())
            except Exception as e:
                logger.error(f"Erro de validação em {func.__name__}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ERROR_MESSAGES["validation_error"]
                )
        return wrapper
    return decorator 
from fastapi import HTTPException, status
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class AppError(Exception):
    """Classe base para erros da aplicação"""
    def __init__(self, message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class DatabaseError(Exception):
    """Exceção para erros de banco de dados."""
    pass

class ValidationError(Exception):
    """Exceção para erros de validação."""
    pass

class NotFoundError(Exception):
    """Exceção para recursos não encontrados."""
    pass

def handle_database_error(error: Exception) -> HTTPException:
    """
    Manipula erros de banco de dados.
    """
    logger.error(f"Erro de banco de dados: {str(error)}", exc_info=True)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Erro ao acessar o banco de dados"
    )

def handle_validation_error(error: Exception) -> HTTPException:
    """
    Manipula erros de validação.
    """
    logger.error(f"Erro de validação: {str(error)}", exc_info=True)
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(error)
    )

def handle_not_found_error(error: Exception) -> HTTPException:
    """
    Manipula erros de recurso não encontrado.
    """
    logger.error(f"Recurso não encontrado: {str(error)}", exc_info=True)
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=str(error)
    )

def handle_general_error(error: Exception) -> HTTPException:
    """
    Manipula erros gerais não tratados.
    """
    logger.error(f"Erro não tratado: {str(error)}", exc_info=True)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Erro interno do servidor"
    )

def handle_duplicate_error(message: str = "Já existe um registro com este nome") -> HTTPException:
    """Trata erros de duplicidade"""
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=message
    ) 
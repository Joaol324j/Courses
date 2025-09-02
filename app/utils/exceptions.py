from fastapi import HTTPException, status
from app.utils.constants import ERROR_MESSAGES

class AppException(HTTPException):
    """
    Exceção base para a aplicação.
    """
    def __init__(
        self,
        status_code: int,
        detail: str,
        headers: dict = None
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)

class NotFoundException(AppException):
    """
    Exceção para recursos não encontrados.
    """
    def __init__(self, detail: str = ERROR_MESSAGES["not_found"]):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail
        )

class UnauthorizedException(AppException):
    """
    Exceção para usuários não autorizados.
    """
    def __init__(self, detail: str = ERROR_MESSAGES["unauthorized"]):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail
        )

class ForbiddenException(AppException):
    """
    Exceção para acesso negado.
    """
    def __init__(self, detail: str = ERROR_MESSAGES["forbidden"]):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )

class ValidationException(AppException):
    """
    Exceção para erros de validação.
    """
    def __init__(self, detail: str = ERROR_MESSAGES["validation_error"]):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail
        )

class DatabaseException(AppException):
    """
    Exceção para erros de banco de dados.
    """
    def __init__(self, detail: str = ERROR_MESSAGES["database_error"]):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class DuplicateEntryException(AppException):
    """
    Exceção para registros duplicados.
    """
    def __init__(self, detail: str = ERROR_MESSAGES["duplicate_entry"]):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail
        )

class RateLimitException(AppException):
    """
    Exceção para limite de requisições excedido.
    """
    def __init__(self, detail: str = "Muitas requisições. Tente novamente mais tarde."):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail
        )

class ServiceUnavailableException(AppException):
    """
    Exceção para serviço indisponível.
    """
    def __init__(self, detail: str = "Serviço temporariamente indisponível."):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail
        )

class BadGatewayException(AppException):
    """
    Exceção para gateway inválido.
    """
    def __init__(self, detail: str = "Gateway inválido."):
        super().__init__(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=detail
        )

class ConflictException(AppException):
    """
    Exceção para conflitos.
    """
    def __init__(self, detail: str = "Conflito de recursos."):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail
        )

class UnsupportedMediaTypeException(AppException):
    """
    Exceção para tipo de mídia não suportado.
    """
    def __init__(self, detail: str = "Tipo de mídia não suportado."):
        super().__init__(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=detail
        ) 
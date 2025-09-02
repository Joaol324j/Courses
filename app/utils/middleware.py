import time
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.utils.constants import ERROR_MESSAGES

logger = logging.getLogger(__name__)

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware para registrar informações sobre cada requisição.
    """
    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        start_time = time.time()
        
        # Log da requisição
        logger.info(
            f"Requisição recebida: {request.method} {request.url.path} "
            f"de {request.client.host}"
        )
        
        try:
            response = await call_next(request)
            
            # Log da resposta
            process_time = time.time() - start_time
            logger.info(
                f"Resposta enviada: {response.status_code} "
                f"em {process_time:.2f} segundos"
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Erro ao processar requisição: {str(e)}")
            raise

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Middleware para tratamento padronizado de erros.
    """
    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        try:
            return await call_next(request)
        except Exception as e:
            logger.error(f"Erro não tratado: {str(e)}")
            return Response(
                content={"detail": ERROR_MESSAGES["database_error"]},
                status_code=500,
                media_type="application/json"
            )

class CORSHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware para adicionar headers CORS.
    """
    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        response = await call_next(request)
        
        # Adiciona headers CORS
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware para limitar taxa de requisições.
    """
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests = {}
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable
    ) -> Response:
        client_ip = request.client.host
        current_time = time.time()
        
        # Limpa requisições antigas
        self.requests = {
            ip: reqs for ip, reqs in self.requests.items()
            if current_time - reqs["timestamp"] < 60
        }
        
        # Verifica limite de requisições
        if client_ip in self.requests:
            if self.requests[client_ip]["count"] >= self.requests_per_minute:
                return Response(
                    content={"detail": "Muitas requisições. Tente novamente mais tarde."},
                    status_code=429,
                    media_type="application/json"
                )
            self.requests[client_ip]["count"] += 1
        else:
            self.requests[client_ip] = {
                "count": 1,
                "timestamp": current_time
            }
        
        return await call_next(request) 
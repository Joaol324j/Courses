import time
from typing import Any, Optional, Dict
from functools import wraps
from app.utils.constants import CACHE

class Cache:
    """
    Implementação simples de cache em memória.
    """
    def __init__(self):
        self._cache: Dict[str, tuple[Any, float]] = {}
    
    def get(self, key: str) -> Optional[Any]:
        """
        Recupera um valor do cache.
        """
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < CACHE["default_ttl"]:
                return value
            del self._cache[key]
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        Armazena um valor no cache.
        """
        ttl = min(ttl or CACHE["default_ttl"], CACHE["max_ttl"])
        self._cache[key] = (value, time.time())
    
    def delete(self, key: str) -> None:
        """
        Remove um valor do cache.
        """
        if key in self._cache:
            del self._cache[key]
    
    def clear(self) -> None:
        """
        Limpa todo o cache.
        """
        self._cache.clear()
    
    def get_size(self) -> int:
        """
        Retorna o número de itens no cache.
        """
        return len(self._cache)
    
    def get_keys(self) -> list[str]:
        """
        Retorna todas as chaves do cache.
        """
        return list(self._cache.keys())

# Instância global do cache
cache = Cache()

def cached(ttl: Optional[int] = None):
    """
    Decorator para cachear resultados de funções.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Gera chave única para o cache
            key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Tenta recuperar do cache
            cached_value = cache.get(key)
            if cached_value is not None:
                return cached_value
            
            # Executa função e armazena resultado
            result = await func(*args, **kwargs)
            cache.set(key, result, ttl)
            return result
        return wrapper
    return decorator

def invalidate_cache(pattern: str):
    """
    Decorator para invalidar cache baseado em padrão.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            
            # Remove entradas do cache que correspondem ao padrão
            keys_to_remove = [
                key for key in cache.get_keys()
                if key.startswith(pattern)
            ]
            for key in keys_to_remove:
                cache.delete(key)
            
            return result
        return wrapper
    return decorator

def cache_key(*args, **kwargs) -> str:
    """
    Gera uma chave de cache a partir de argumentos.
    """
    key_parts = []
    if args:
        key_parts.extend(str(arg) for arg in args)
    if kwargs:
        key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))
    return ":".join(key_parts)

def with_cache(ttl: Optional[int] = None):
    """
    Decorator para cachear resultados de funções com chave personalizada.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            key = cache_key(*args, **kwargs)
            
            # Tenta recuperar do cache
            cached_value = cache.get(key)
            if cached_value is not None:
                return cached_value
            
            # Executa função e armazena resultado
            result = await func(*args, **kwargs)
            cache.set(key, result, ttl)
            return result
        return wrapper
    return decorator

def clear_cache(pattern: str = None):
    """
    Limpa o cache, opcionalmente filtrando por padrão.
    """
    if pattern:
        keys_to_remove = [
            key for key in cache.get_keys()
            if key.startswith(pattern)
        ]
        for key in keys_to_remove:
            cache.delete(key)
    else:
        cache.clear() 
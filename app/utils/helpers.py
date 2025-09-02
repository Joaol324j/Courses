from typing import Any, Dict, Optional, List
from datetime import datetime
from fastapi import HTTPException, status
import os
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def format_datetime(dt: datetime) -> str:
    """
    Formata uma data/hora para string ISO.
    """
    return dt.isoformat() if dt else None

def parse_datetime(dt_str: str) -> Optional[datetime]:
    """
    Converte uma string ISO para datetime.
    """
    try:
        return datetime.fromisoformat(dt_str) if dt_str else None
    except ValueError:
        return None

def remove_none_values(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove valores None de um dicionário.
    """
    return {k: v for k, v in data.items() if v is not None}

def validate_pagination_params(
    skip: int = 0,
    limit: int = 100,
    max_limit: int = 1000
) -> tuple[int, int]:
    """
    Valida e ajusta parâmetros de paginação.
    """
    if skip < 0:
        skip = 0
    if limit < 1:
        limit = 1
    if limit > max_limit:
        limit = max_limit
    return skip, limit

def load_json_file(file_path: str) -> Dict[str, Any]:
    """
    Carrega um arquivo JSON.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Erro ao carregar arquivo JSON {file_path}: {str(e)}")
        raise

def save_json_file(data: Dict[str, Any], file_path: str) -> None:
    """
    Salva dados em um arquivo JSON.
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erro ao salvar arquivo JSON {file_path}: {str(e)}")
        raise

def ensure_directory(directory: str) -> None:
    """
    Garante que um diretório existe.
    """
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Erro ao criar diretório {directory}: {str(e)}")
        raise

def get_file_extension(filename: str) -> str:
    """
    Retorna a extensão de um arquivo.
    """
    return os.path.splitext(filename)[1].lower()

def format_file_size(size_bytes: int) -> str:
    """
    Formata o tamanho de um arquivo em bytes para uma string legível.
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

def generate_unique_filename(original_filename: str) -> str:
    """
    Gera um nome de arquivo único baseado no timestamp.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    extension = get_file_extension(original_filename)
    return f"{timestamp}{extension}"

def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Divide uma lista em chunks de tamanho específico.
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def flatten_list(lst: List[List[Any]]) -> List[Any]:
    """
    Aplaina uma lista de listas.
    """
    return [item for sublist in lst for item in sublist]

def remove_duplicates(lst: List[Any]) -> List[Any]:
    """
    Remove duplicatas de uma lista mantendo a ordem.
    """
    return list(dict.fromkeys(lst))

def safe_get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """
    Recupera um valor de um dicionário de forma segura.
    """
    current = d
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current 
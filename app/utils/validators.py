from typing import Any, Dict, Optional
from fastapi import HTTPException, status
from app.schemas.course_schema import CursoCreate, CursoUpdate
from app.schemas.student_schema import StudentCreate, StudentUpdate
from app.schemas.enrollment_schema import EnrollmentCreate, EnrollmentUpdate
import re
from app.utils.constants import ERROR_MESSAGES
from app.utils.exceptions import ValidationException

def validate_curso_data(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Valida os dados do curso antes de criar ou atualizar.
    Retorna os dados validados ou lança uma exceção.
    """
    if not data.get("name"):
        raise ValidationException("O nome do curso é obrigatório")
    
    if not data.get("description"):
        raise ValidationException("A descrição do curso é obrigatória")
    
    if not data.get("time") or not isinstance(data["time"], int) or data["time"] < 1:
        raise ValidationException("A duração do curso deve ser um número inteiro maior que zero")
    
    return {
        "name": data["name"].strip(),
        "description": data["description"].strip(),
        "time": data["time"]
    }

def validate_course_data(course: CursoCreate) -> None:
    """
    Valida os dados de um curso antes de criar ou atualizar.
    """
    if not course.name or len(course.name.strip()) < 1:
        raise ValidationException("O nome do curso é obrigatório e não pode estar vazio")
    
    if not course.description or len(course.description.strip()) < 1:
        raise ValidationException("A descrição do curso é obrigatória e não pode estar vazia")
    
    if not course.time or course.time < 1:
        raise ValidationException("A duração do curso deve ser maior que zero")

def validate_student_data(student: StudentCreate) -> None:
    """
    Valida os dados de um aluno antes de criar ou atualizar.
    """
    if not student.name or len(student.name.strip()) < 1:
        raise ValidationException("O nome do aluno é obrigatório e não pode estar vazio")
    
    if not student.email or len(student.email.strip()) < 1:
        raise ValidationException("O email do aluno é obrigatório e não pode estar vazio")

def validate_enrollment_data(enrollment: EnrollmentCreate) -> None:
    """
    Valida os dados de uma matrícula antes de criar ou atualizar.
    """
    if not enrollment.student_id:
        raise ValidationException("O ID do aluno é obrigatório")
    
    if not enrollment.course_id:
        raise ValidationException("O ID do curso é obrigatório")

def validate_email(email: str) -> bool:
    """
    Valida formato de email.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> bool:
    """
    Valida força da senha.
    Requisitos:
    - Mínimo 8 caracteres
    - Pelo menos uma letra maiúscula
    - Pelo menos uma letra minúscula
    - Pelo menos um número
    - Pelo menos um caractere especial
    """
    if len(password) < 8:
        return False
    
    if not re.search(r'[A-Z]', password):
        return False
    
    if not re.search(r'[a-z]', password):
        return False
    
    if not re.search(r'\d', password):
        return False
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    return True

def validate_phone(phone: str) -> bool:
    """
    Valida formato de telefone.
    Aceita formatos:
    - (XX) XXXXX-XXXX
    - XX XXXXX-XXXX
    - XXXXXXXXXXX
    """
    pattern = r'^\(?[0-9]{2}\)?[0-9]{5}-?[0-9]{4}$'
    return bool(re.match(pattern, phone))

def validate_cpf(cpf: str) -> bool:
    """
    Valida CPF.
    """
    # Remove caracteres não numéricos
    cpf = re.sub(r'[^0-9]', '', cpf)
    
    if len(cpf) != 11:
        return False
    
    # Verifica CPFs com números iguais
    if cpf == cpf[0] * 11:
        return False
    
    # Validação do primeiro dígito verificador
    soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
    digito1 = 11 - (soma % 11)
    if digito1 > 9:
        digito1 = 0
    
    # Validação do segundo dígito verificador
    soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
    digito2 = 11 - (soma % 11)
    if digito2 > 9:
        digito2 = 0
    
    return int(cpf[9]) == digito1 and int(cpf[10]) == digito2

def validate_cnpj(cnpj: str) -> bool:
    """
    Valida CNPJ.
    """
    # Remove caracteres não numéricos
    cnpj = re.sub(r'[^0-9]', '', cnpj)
    
    if len(cnpj) != 14:
        return False
    
    # Verifica CNPJs com números iguais
    if cnpj == cnpj[0] * 14:
        return False
    
    # Validação do primeiro dígito verificador
    pesos = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    soma = sum(int(cnpj[i]) * pesos[i] for i in range(12))
    digito1 = 11 - (soma % 11)
    if digito1 > 9:
        digito1 = 0
    
    # Validação do segundo dígito verificador
    pesos = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    soma = sum(int(cnpj[i]) * pesos[i] for i in range(13))
    digito2 = 11 - (soma % 11)
    if digito2 > 9:
        digito2 = 0
    
    return int(cnpj[12]) == digito1 and int(cnpj[13]) == digito2

def validate_url(url: str) -> bool:
    """
    Valida formato de URL.
    """
    pattern = r'^https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$'
    return bool(re.match(pattern, url))

def validate_date(date_str: str) -> bool:
    """
    Valida formato de data (YYYY-MM-DD).
    """
    pattern = r'^\d{4}-\d{2}-\d{2}$'
    if not re.match(pattern, date_str):
        return False
    
    try:
        year, month, day = map(int, date_str.split('-'))
        if not (1900 <= year <= 2100):
            return False
        if not (1 <= month <= 12):
            return False
        if not (1 <= day <= 31):  # Simplificado, pode ser melhorado
            return False
        return True
    except ValueError:
        return False

def validate_student_data(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Valida dados de um estudante.
    """
    if not data.get("name"):
        raise ValidationException("O nome do estudante é obrigatório")
    
    if not data.get("email"):
        raise ValidationException("O email do estudante é obrigatório")
    
    if not validate_email(data["email"]):
        raise ValidationException("Email inválido")
    
    return data

def validate_enrollment_data(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Valida dados de uma matrícula.
    """
    if not data.get("student_id"):
        raise ValidationException("O ID do estudante é obrigatório")
    
    if not data.get("course_id"):
        raise ValidationException("O ID do curso é obrigatório")
    
    return data 
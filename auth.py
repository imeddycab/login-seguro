from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import models
import schemas

# Configuración de seguridad
SECRET_KEY = "tu_clave_secreta_muy_segura_cambiar_en_produccion"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Contexto de hashing con bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    """Verifica la contraseña plana contra el hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Genera hash de la contraseña"""
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    """Obtiene usuario por username o email"""
    return db.query(models.User).filter(
        (models.User.username == username) | (models.User.email == username)
    ).first()

def authenticate_user(db: Session, username: str, password: str):
    """Autentica usuario verificando credenciales"""
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Crea token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
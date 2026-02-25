from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from typing import Optional, Annotated
from datetime import datetime, timedelta
import re

import models
import schemas
from database import engine, get_db
import auth

# Crear tablas en la BD
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Login Seguro con FastAPI")

# Configuración de templates
templates = Jinja2Templates(directory="templates")

# Esquema OAuth2 para el token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependencia para obtener usuario actual
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = auth.get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    
    return user

# Dependencia para usuario activo
async def get_current_active_user(
    current_user: schemas.UserResponse = Depends(get_current_user)
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Usuario inactivo")
    return current_user

# ========== ENDPOINTS ==========

# 1. REGISTRO DE USUARIO
@app.post("/register", response_model=schemas.UserResponse)
async def register_user(
    user_data: schemas.UserCreate,
    db: Session = Depends(get_db)
):
    """
    Registro de nuevo usuario con validaciones y hash de contraseña
    """
    # Verificar si el usuario ya existe
    db_user = db.query(models.User).filter(
        (models.User.username == user_data.username) | 
        (models.User.email == user_data.email)
    ).first()
    
    if db_user:
        if db_user.username == user_data.username:
            raise HTTPException(
                status_code=400,
                detail="El nombre de usuario ya está registrado"
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="El email ya está registrado"
            )
    
    # Crear nuevo usuario con contraseña hasheada
    hashed_password = auth.get_password_hash(user_data.password)
    
    db_user = models.User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hashed_password,
        full_name=user_data.full_name
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

# 2. INICIO DE SESIÓN (Genera token)
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Endpoint para obtener token de acceso (login)
    """
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    
    # Mensaje genérico por seguridad
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Crear token
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# 3. PÁGINA PROTEGIDA (HTML)
@app.get("/protected-page", response_class=HTMLResponse)
async def protected_page(
    request: Request,
    current_user: schemas.UserResponse = Depends(get_current_active_user)
):
    """
    Página protegida que solo muestra si el usuario está autenticado
    """
    return templates.TemplateResponse(
        "protected.html",
        {
            "request": request,
            "user": current_user
        }
    )

# Endpoint protegido simple (JSON)
@app.get("/users/me", response_model=schemas.UserResponse)
async def read_users_me(
    current_user: schemas.UserResponse = Depends(get_current_active_user)
):
    """
    Endpoint protegido que retorna información del usuario actual
    """
    return current_user

# Login alternativo (formulario simple)
@app.post("/login", response_model=schemas.Token)
async def login_simple(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Login alternativo usando Form en lugar de OAuth2
    """
    user = auth.authenticate_user(db, username, password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas"
        )
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
async def root():
    return {
        "message": "API de Login Seguro",
        "endpoints": {
            "registro": "POST /register",
            "login": "POST /token o POST /login",
            "perfil_protegido": "GET /users/me (requiere token)",
            "pagina_protegida": "GET /protected-page (requiere token)"
        }
    }
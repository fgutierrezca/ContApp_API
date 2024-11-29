import os
import secrets
import hashlib
import base64
import jwt

from datetime import datetime, timedelta
from fastapi import HTTPException
from dotenv import load_dotenv
from jwt import PyJWTError
from functools import wraps

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
SECRET_KEY_FUNC = os.getenv("SECRET_KEY_FUNC")

# Función para crear un JWT
def create_jwt_token(firstname:str, lastname:str, email: str, active: bool):
    expiration = datetime.now() + timedelta(hours=1)  # El token expira en 1 hora
    token = jwt.encode(
        {
            "firstname": firstname,
            "lastname": lastname,
            "email": email,
            "active": active,
            "exp": expiration,
            "iat": datetime.now()
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    return token

# Crear un decorador para validar el JWT
def validate(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get('request')
        if not request:
            raise HTTPException(status_code=400, detail="Request object not found")

        authorization: str = request.headers.get("Authorization")
        if not authorization:
            raise HTTPException(status_code=400, detail="Authorization header missing")


        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=400, detail="Invalid authentication scheme")

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


            email = payload.get("email")
            expired = payload.get("exp")
            active = payload.get("active")
            firstname = payload.get("firstname")
            lastname = payload.get("lastname")



            if email is None or expired is None or active is None:
                raise HTTPException(status_code=400, detail="Invalid token")

            if datetime.fromtimestamp(expired) < datetime.now():
                raise HTTPException(status_code=401, detail="Expired token")

            if not active:
                raise HTTPException(status_code=403, detail="Inactive user")

            # Inyectar el email en el objeto request
            request.state.email = email
            request.state.firstname = firstname
            request.state.lastname = lastname
        except PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token or expired token")



        return await func(*args, **kwargs)
    return wrapper

def validate_for_inactive(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get('request')
        if not request:
            raise HTTPException(status_code=400, detail="Request object not found")

        authorization: str = request.headers.get("Authorization")
        if not authorization:
            raise HTTPException(status_code=400, detail="Authorization header missing")

        try:
            scheme, token = authorization.split()
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=400, detail="Invalid authentication scheme")

            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

            email = payload.get("email")
            expired = payload.get("exp")

            if email is None or expired is None:
                raise HTTPException(status_code=400, detail="Invalid token")

            if datetime.fromtimestamp(expired) < datetime.now():
                raise HTTPException(status_code=401, detail="Expired token")



            # Inyectar el email en el objeto request
            request.state.email = email
        except PyJWTError:
            raise HTTPException(status_code=403, detail="Invalid token or expired token")

        return await func(*args, **kwargs)
    return wrapper

# Metodo propio de autenticacion de la function app para poder generar el codigo de activacion
def validate_func(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get('request')
        
        # Verificar que el request si exista
        if not request:
            raise HTTPException(status_code=400, detail="Request object not found")

        # Que en el header se encuentre el campo Authorization
        authorization: str = request.headers.get("Authorization")
        if not authorization:
            raise HTTPException(status_code=403, detail="Authorization header missing")

        # En caso que sea distinto a la SECRET_KEY_FUNC
        if authorization != SECRET_KEY_FUNC:
            raise HTTPException(status_code=403, detail="Wrong function key")

        return await func(*args, **kwargs)
    return wrapper
import logging
from datetime import timedelta, datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4
from fastapi import Depends
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from passlib.handlers.bcrypt import bcrypt
from sqlalchemy.orm import Session
from sqlalchemy.util import deprecated

from entities.user import User
from . import model
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from ..exceptions import AuthenticationError

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)


def authenticate_user(email: str, password: str, db: Session) -> User | bool:
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password - hash):
        logging.warning(f"Failed authentication attempt for email:{email}")
        return False
    return user

def create_access_token(email:str,user_id:UUID,expires_delta:timedelta)->str:
    encode = {
        'sub':email,
        'id':str(user_id),
        'exp':datetime.now(timezone.utc) + expires_delta
    }
    return jwt.encode(encode,SECRET_KEY,algorithm=[ALGORITHM])

def verify_token(token:str)->model.TokenData:
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        user_id:str=payload.get('id')
        return model.TokenData(user_id=user_id)
    except PyJWTError as e :
        logging.warning(f"Token verification failed:{str(e)}")
        raise AuthenticationError()

def register_user(db:Session)
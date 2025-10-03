import logging
from datetime import timedelta, datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4
from fastapi import Depends, HTTPException, status  # Added HTTPException and status
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
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Corrected the variable name for use in login_for_access_token

oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)


def get_db():
    # Placeholder: Replace with your actual DB session logic
    raise NotImplementedError("Database session dependency 'get_db' must be implemented.")


def authenticate_user(email: str, password: str, db: Session) -> User | None:  # Changed return type hint
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        logging.warning(f"Failed authentication attempt for email: {email}")
        return None
    return user


def create_access_token(email: str, user_id: UUID, expires_delta: timedelta) -> str:
    encode = {
        'sub': email,
        'id': str(user_id),
        'exp': datetime.now(timezone.utc) + expires_delta
    }
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> model.TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get('id')
        if user_id is None:
            raise PyJWTError("User ID not found in token payload")
        return model.TokenData(user_id=user_id)
    except PyJWTError as e:
        logging.warning(f"Token verification failed: {str(e)}")
        raise AuthenticationError()


def register_user(db: Session, register_user_request: model.RegisterUserRequest) -> None:
    try:
        create_user_model = User(
            id=uuid4(),
            email=register_user_request.email,
            first_name=register_user_request.first_name,
            last_name=register_user_request.last_name,
            # FIX 4: Corrected column name to 'password_hash' to match User entity
            password_hash=get_password_hash(register_user_request.password)
        )
        db.add(create_user_model)
        db.commit()
    except Exception as e:
        logging.error(f"Failed to register user: {register_user_request.email}. Error: {str(e)}")
        # Re-raise the exception or raise a more specific one for the user
        raise


def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]) -> model.TokenData:
    return verify_token(token)


CurrentUser = Annotated[model.TokenData, Depends(get_current_user)]


def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Annotated[Session, Depends(get_db)]
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        email=user.email,
        user_id=user.id,
        expires_delta=access_token_expires
    )

    return model.Token(access_token=token, token_type='bearer')

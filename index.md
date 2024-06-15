---
title: "Home"
layout: default
permalink: /all-python-fastapi/
--- 

[Home](index.md) | [Virtual Env](venv.md) 

### Table of Contents {#toc}
- [Set-up and Running the App](#venv)
- [Project structure](#structure)
- [Main](#main)
- [Email](#email)
- [Auth](#auth)
- [Dependencies](#dependencies)
- [Config](#config)
- [Endpoints](#endpoints)
                             
### Set-up and Running the App {#venv}
Creating a virtual environment
```bash
git clone <repository-url>
cd fastapi_app
python -m venv venv # Alternatively, python3.10 -m  venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
```
To run the application in Dev
```bash
uvicorn app.main:app --reload --port 8001
```
##### Note:
- --reload enables the auto-reload feature, useful for development. 


To run the application in Prod
```bash
pip install gunicorn # add this to the requirements.txt
gunicorn -k uvicorn.workers.UvicornWorker app.main:app --bind 0.0.0.0:8000 --workers 4

```
##### Note:
- -k uvicorn.workers.UvicornWorker specifies the worker class to use uvicorn workers.
- --bind specifies the address and port to bind the server to.
- --workers specifies the number of worker processes to handle requests.

#### [Back to TOC](#toc)
#### Project structure - Email API{#structure}

```
fastapi_app/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── models/
│   │   ├── __init__.py
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── email.py
│   │   ├── auth.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── email.py
│   │   ├── auth.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── email.py
│   │   ├── auth.py
│   ├── config.py
│   ├── dependencies.py
│
├── requirements.txt
├── README.md
└── .env
```
##### Note:
- main.py: The entry point of the application.
- models: Contains the data schema or structure
- routes/: Contains the API endpoints.
- schemas/: Contains the Pydantic models (schemas) for request and response bodies.
- services/: Contains the business logic for handling requests.
- config.py: Configuration settings for the application.
- dependencies.py: Contains dependencies like authentication.

#### [Back to TOC](#toc)
### Main{#main}
==app/main.py==
```python
from fastapi import FastAPI
from app.database import Base, engine
from app.routes.email import router as email_router
from app.routes.auth import router as auth_router

app = FastAPI()

# Create the database tables
Base.metadata.create_all(bind=engine)

@app.get("/")
def read_root():
    return {"message": "Welcome to the FastAPI application!"}

app.include_router(email_router, prefix="/email", tags=["Email"])
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
```

==app/database.py==
```python
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Email(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, index=True)
    email_address = Column(String, unique=True, index=True)

Base.metadata.create_all(bind=engine)
```

#### [Back to TOC](#toc)
### Email {#email}
==app/routes/email.py==
```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db, Email
from app.dependencies import get_current_user, get_current_admin_user
from app.schemas.email import EmailCreate, EmailUpdate, Email as EmailSchema

email_router = APIRouter()

fake_email_db = []

@email_router.get("/", response_model=List[EmailSchema])
def read_emails(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    emails = db.query(Email).all()
    if not emails:
        return fake_email_db
    return emails

@email_router.post("/", response_model=EmailSchema)
def create_email(email: EmailCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    db_email = db.query(Email).filter(Email.email_address == email.email_address).first()
    if db_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_email = Email(email_address=email.email_address)
    db.add(db_email)
    db.commit()
    db.refresh(db_email)
    return db_email

@email_router.put("/{email_id}", response_model=EmailSchema)
def update_email(email_id: int, email: EmailUpdate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    db_email = db.query(Email).filter(Email.id == email_id).first()
    if not db_email:
        raise HTTPException(status_code=404, detail="Email not found")
    db_email.email_address = email.email_address
    db.commit()
    db.refresh(db_email)
    return db_email

@email_router.delete("/{email_id}", response_model=EmailSchema)
def delete_email(email_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    db_email = db.query(Email).filter(Email.id == email_id).first()
    if not db_email:
        raise HTTPException(status_code=404, detail="Email not found")
    db.delete(db_email)
    db.commit()
    return db_email
```

==app/schemas/email.py==
```python
from pydantic import BaseModel

class EmailBase(BaseModel):
    email_address: str

class EmailCreate(EmailBase):
    pass

class EmailUpdate(EmailBase):
    pass

class Email(EmailBase):
    id: int

    class Config:
        orm_mode: True
```

==app/services/email.py==
```python
from typing import List, Optional
from app.schemas.email import EmailSchema, EmailUpdateSchema

fake_email_db = [
    {"id": 1, "email": "user1@example.com"},
    {"id": 2, "email": "user2@example.com"}
]

class EmailService:
    @staticmethod
    def get_all_emails() -> List[EmailSchema]:
        return [EmailSchema(**email) for email in fake_email_db]

    @staticmethod
    def add_email(email: EmailSchema) -> EmailSchema:
        new_id = max(email["id"] for email in fake_email_db) + 1 if fake_email_db else 1
        new_email = EmailSchema(id=new_id, email=email.email)
        fake_email_db.append(new_email.dict())
        return new_email

    @staticmethod
    def update_email(email_id: int, email: EmailUpdateSchema) -> Optional[EmailSchema]:
        for index, existing_email in enumerate(fake_email_db):
            if existing_email["id"] == email_id:
                updated_email = EmailSchema(id=email_id, email=email.email)
                fake_email_db[index] = updated_email.dict()
                return updated_email
        return None

    @staticmethod
    def delete_email(email_id: int) -> Optional[EmailSchema]:
        for index, existing_email in enumerate(fake_email_db):
            if existing_email["id"] == email_id:
                deleted_email = EmailSchema(**existing_email)
                del fake_email_db[index]
                return deleted_email
        return None
```
#### [Back to TOC](#toc)
### Auth{#auth}
==app/routes/auth.py==
```python
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from app.schemas.auth import Token
from app.services.auth import AuthService
from app.config import settings

auth_router = APIRouter()

@auth_router.post("/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = AuthService.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = AuthService.create_access_token(
        data={"sub": user["username"], "role": user["role"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
```

==app/routes/auth.py==
```python
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from app.schemas.auth import Token
from app.services.auth import AuthService

router = APIRouter()

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = AuthService.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = AuthService.create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer"}
```

==app/schemas/auth.py==
```python
from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str
```

==app/services/auth.py==
```python
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.schemas.auth import Token
from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_users_db = {
    "admin": {
        "username": "admin",
        "full_name": "Admin User",
        "email": "admin@example.com",
        "hashed_password": pwd_context.hash("password"),
        "role": "admin",
        "disabled": False,
    },
    "user": {
        "username": "user",
        "full_name": "Normal User",
        "email": "user@example.com",
        "hashed_password": pwd_context.hash("password"),
        "role": "user",
        "disabled": False,
    }
}

class AuthService:
    @staticmethod
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_user(db, username: str):
        if username in db:
            user_dict = db[username]
            return user_dict
        return None

    @staticmethod
    def authenticate_user(username: str, password: str):
        user = AuthService.get_user(fake_users_db, username)
        if not user:
            return False
        if not AuthService.verify_password(password, user["hashed_password"]):
            return False
        return user

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
        return encoded_jwt
```

#### [Back to TOC](#toc)
### Dependencies{#dependencies}
==app/dependencies.py==
```python
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from app.services.auth import AuthService
from app.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = AuthService.get_user(AuthService.fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user

def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Not enough permissions",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user
```

#### [Back to TOC](#toc)
### Config{#config}
==app/config.py==
```python
from pydantic import BaseSettings

class Settings(BaseSettings):
    secret_key: str = "your_secret_key"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    class Config:
        env_file = ".env"

settings = Settings()
```

==app/.env==
```python
SECRET_KEY=your_secret_key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

==requirements.txt==
```
fastapi
uvicorn
pydantic
python-jose[cryptography]
passlib[bcrypt]
python-dotenv
sqlalchemy
sqlite
```

==README.md==
```markdown
# FastAPI Boilerplate for Email Management

This is a basic boilerplate for a FastAPI application with authentication and email management, including role-based authorization.

## Installation

1. Clone the repository
2. Create a virtual environment and activate it
3. Install the dependencies
```

#### [Back to TOC](#toc)
### Endpoints{#endpoints}

##### Auth API
- `POST /auth/login:` Log in to get a JWT token.

##### Email API
- `GET /email/:` Get all email addresses (accessible by normal users and admin users).
- `POST /email/:` Add a new email address (accessible by admin users only).
- `PUT /email/{email_id}:` Update an email address by ID (accessible by admin users only).
- `DELETE /email/{email_id}:` Delete an email address by ID (accessible by admin users only).



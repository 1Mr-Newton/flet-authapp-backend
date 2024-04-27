from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Text

from sqlalchemy.orm import sessionmaker, Session, declarative_base
from datetime import datetime, timedelta

# Configuration and security
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10
REFRESH_TOKEN_EXPIRE_TIME = 30
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

# Database setup
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    refresh_token = Column(Text, nullable=True)


Base.metadata.create_all(bind=engine)

app = FastAPI()
router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.hashed_password):
        return user
    return None


def create_refresh_token(user_id: int):
    expires_delta = timedelta(seconds=REFRESH_TOKEN_EXPIRE_TIME)
    to_encode = {"sub": str(user_id), "exp": datetime.utcnow() + expires_delta}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@router.post("/token", response_model=dict)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(int(str(user.id)))
    user.refresh_token = Column(refresh_token)
    db.commit()
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh")
async def refresh_access_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )
        user = (
            db.query(User)
            .filter(User.id == user_id, User.refresh_token == refresh_token)
            .first()
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
            )
        access_token = create_access_token(data={"sub": user.username})
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me")
async def read_users_me(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
):

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        user_dict = user.__dict__
        user_dict.pop("hashed_password")
        return user_dict
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


app.include_router(router)


username = "testuser"
password = "test123."


def create_fake_user():
    db = SessionLocal()
    db.add(User(username=username, hashed_password=get_password_hash(password)))
    db.commit()
    db.close()


# create_fake_user()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

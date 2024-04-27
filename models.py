from sqlalchemy import Column, Integer, String, Text
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), nullable=False, unique=True)
    hashed_password = Column(String(100), nullable=False)

from fastapi import FastAPI, Depends, HTTPException, status

from database import engine
from typing import Annotated
from sqlalchemy.orm import Session
import models
from helpers import get_db
import auth
from auth import get_current_user

app = FastAPI()
app.include_router(auth.router)

models.Base.metadata.create_all(bind=engine)

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[models.User, Depends(get_current_user)]


@app.get("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"user": user}

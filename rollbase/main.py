from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import List
from . import crud, models, schemas, utils
from .database import SessionLocal, engine

# Initialize the database
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# OAuth2PasswordBearer helps us to get the token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Signup endpoint
@app.post("/signup", response_model=schemas.UserOut)
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)

# Login endpoint
@app.post("/login")
def login(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if not db_user or not crud.verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = utils.create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Protect route to demonstrate authenticated access
@app.get("/users/me", response_model=schemas.UserOut)
def get_user_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = utils.verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    db_user = crud.get_user_by_email(db, email=payload.get("sub"))
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

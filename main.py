from fastapi import FastAPI, Depends, HTTPException, status,Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import pymysql
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
import time
from collections import deque
from functools import wraps

app = FastAPI()

DB_HOST = "localhost"
DB_PORT = 3306
DB_USER = "root"
DB_PASSWORD = ""
DB_NAME = "mydatabase"


SECRET_KEY = "thong"  
ALGORITHM = "HS256"  
ACCESS_TOKEN_EXPIRE_MINUTES = 30  


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        db=DB_NAME
    )

class User(BaseModel):
    username: str
    password: str
def rate_limiter(time_frame: int, max_calls: int):
    def decorator(func):
        calls = deque()

        @wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()

            while calls and current_time - calls[0] > time_frame:
                calls.popleft()

            if len(calls) >= max_calls:
                raise Exception(f"Rate limit exceeded: {max_calls} requests per {time_frame} seconds.")
            
            calls.append(current_time)
            
            return func(*args, **kwargs)

        return wrapper
    return decorator

def verify_credentials(username: str, password: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s",
                (username, password),
            )
            user = cursor.fetchone()
            if user:
                return user
            else:
                return None
    finally:
        conn.close()


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception


def login_for_access_token(form_data: User):
    user = verify_credentials(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/login")
@rate_limiter(time_frame=60,max_calls=10)
def login_for_access_token(form_data: User):
    user = verify_credentials(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/create")
@rate_limiter(time_frame=60,max_calls=10)
def create_user(user: User, token: str = Depends(verify_token)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (user.username, user.password),
            )
            conn.commit()
            return {"message": "User created successfully","username":user.username,"password":user.password}
    finally:
        conn.close()

@app.get("/get")
@rate_limiter(time_frame=60,max_calls=10)
def get_user(token: str = Depends(verify_token)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "select * from users"
            )
            users = cursor.fetchall()
            user_list = [
                {"id": user[0], "username": user[1], "password": user[2]}
                for user in users
            ]
            return user_list
    finally:
        conn.close()

@app.delete("/delete/{id}")
@rate_limiter(time_frame=60,max_calls=10)
def delete_user(id :int, token: str = Depends(verify_token)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("select * from users where id = %s", (id,))
            user = cursor.fetchone()
            if user is None:
                raise HTTPException(status_code=404, detail=f"User with id {id} not found")
            
            cursor.execute("delete from users where id = %s", (id,))
            conn.commit()
            return {"message": f"User with id {id} has been deleted successfully."}
    finally:
        conn.close()

@app.put("/edit/{id}")
@rate_limiter(time_frame=60,max_calls=10)
def update_user(id, user: User):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (id,))
            existing_user = cursor.fetchone()
            if existing_user is None:
                raise HTTPException(status_code=404, detail=f"User with id {id} not found")
            cursor.execute(
                "UPDATE users SET username = %s, password = %s WHERE id = %s",
                (user.username, user.password, id)
            )
            conn.commit()
            return {"message": f"User with id {id} has been updated successfully.",
                    "username": user.username, "password": user.password}
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8081, reload=True)

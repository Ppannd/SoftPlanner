import os
import random
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Union
from fastapi import FastAPI, HTTPException, Depends, status, WebSocket
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.responses import JSONResponse

# Настройки
SECRET_KEY = "your-secret-key-here-1234567890"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 часа

# Модели данных
class UserBase(BaseModel):
    email: EmailStr
    name: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str = Field(..., min_length=6, max_length=6)  # 6-значный ID
    hashed_password: str
    language: str = "ru"
    theme: str = "dark"
    workspaces: List[str] = []
    disabled: bool = False

class UserInDB(User):
    pass

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class Notification(BaseModel):
    id: str
    type: str  # "invite" или "reminder"
    title: str
    message: str
    timestamp: str
    read: bool = False
    workspace_id: Optional[str] = None
    task_id: Optional[str] = None

class Workspace(BaseModel):
    id: str
    name: str
    members: List[str]  # список user_id
    created_at: datetime

# Инициализация
app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Включение CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# "База данных" в памяти
fake_db = {
    "users": {},
    "workspaces": {},
    "notifications": {}
}

# Вспомогательные функции
def generate_user_id():
    return str(random.randint(100000, 999999))

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = fake_db["users"].get(token_data.email)
    if user is None:
        raise credentials_exception
    return user

# API Endpoints
@app.post("/register", response_model=User)
async def register(user: UserCreate):
    if user.email in fake_db["users"]:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = generate_user_id()
    hashed_password = get_password_hash(user.password)
    db_user = UserInDB(
        id=user_id,
        email=user.email,
        name=user.name,
        hashed_password=hashed_password,
    )
    
    fake_db["users"][user.email] = db_user.dict()
    return db_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_db["users"].get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    user = UserInDB(**user_dict)
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/users/me", response_model=User)
async def update_user_profile(
    name: Optional[str] = None,
    language: Optional[str] = None,
    theme: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    user_data = fake_db["users"][current_user.email]
    if name:
        user_data["name"] = name
    if language:
        user_data["language"] = language
    if theme:
        user_data["theme"] = theme
    
    fake_db["users"][current_user.email] = user_data
    return User(**user_data)

@app.post("/workspaces/", response_model=Workspace)
async def create_workspace(
    name: str,
    current_user: User = Depends(get_current_user),
):
    workspace_id = str(random.randint(100000, 999999))
    workspace = Workspace(
        id=workspace_id,
        name=name,
        members=[current_user.id],
        created_at=datetime.utcnow(),
    )
    fake_db["workspaces"][workspace_id] = workspace.dict()
    
    # Обновляем список workspace у пользователя
    user_data = fake_db["users"][current_user.email]
    user_data["workspaces"].append(workspace_id)
    fake_db["users"][current_user.email] = user_data
    
    return workspace

@app.post("/workspaces/{workspace_id}/invite")
async def invite_to_workspace(
    workspace_id: str,
    user_id: str,
    current_user: User = Depends(get_current_user),
):
    # Проверяем что workspace существует и текущий пользователь в нём
    workspace = fake_db["workspaces"].get(workspace_id)
    if not workspace or current_user.id not in workspace["members"]:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")
    
    # Проверяем что приглашаемый пользователь существует
    invited_user = None
    for user in fake_db["users"].values():
        if user["id"] == user_id:
            invited_user = user
            break
    
    if not invited_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Создаём уведомление
    notification_id = str(random.randint(100000, 999999))
    notification = Notification(
        id=notification_id,
        type="invite",
        title="Приглашение в рабочее пространство",
        message=f"{current_user.name} приглашает вас в {workspace['name']}",
        timestamp=datetime.utcnow().isoformat(),
        workspace_id=workspace_id,
    )
    
    if user_id not in fake_db["notifications"]:
        fake_db["notifications"][user_id] = []
    fake_db["notifications"][user_id].append(notification.dict())
    
    return {"message": "Invitation sent"}

@app.get("/notifications", response_model=List[Notification])
async def get_notifications(current_user: User = Depends(get_current_user)):
    return fake_db["notifications"].get(current_user.id, [])

@app.post("/notifications/{notification_id}/read")
async def mark_notification_as_read(
    notification_id: str,
    current_user: User = Depends(get_current_user)):
    notifications = fake_db["notifications"].get(current_user.id, [])
    for notification in notifications:
        if notification["id"] == notification_id:
            notification["read"] = True
            break
    return {"message": "Notification marked as read"}

# WebSocket для уведомлений
active_connections = {}

@app.websocket("/ws/notifications/{user_id}")
async def websocket_notifications(websocket: WebSocket, user_id: str):
    await websocket.accept()
    active_connections[user_id] = websocket
    
    try:
        while True:
            # Можно добавить ping-pong для поддержания соединения
            await websocket.receive_text()
    except:
        active_connections.pop(user_id, None)

def send_notification(user_id: str, notification: Notification):
    if user_id in active_connections:
        websocket = active_connections[user_id]
        websocket.send_json(notification.dict())

# Запуск (для разработки)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone

#Config basica
SECRET_KEY = "hola"
ALGORITHM = "HS256" #Hash-based Message Authentication Code
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

usersDB = {}
oauth2Scheme = OAuth2PasswordBearer(tokenUrl="token")
pwdContext = CryptContext(schemes=["bcrypt"], deprecated="auto")

#Auth, modelo de usuarios y hashing
class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    accessToken: str
    tokenType: str

def verifyPassword(plainPassword, hashedPassword):
    return pwdContext.verify(plainPassword, hashedPassword)

def getPasswordHash(password):
    return pwdContext.hash(password)

def getUser(db, username: str):
    if username in db:
        userDict = db[username]
        return User(**userDict)

def authenticateUser(usersDB, username: str, password: str):
    user = getUser(usersDB, username)
    if not user or not verifyPassword(password, user.password):
        return False
    return user

def createAccessToken(data: dict, expiresDelta: timedelta = None):
    encode = data.copy()
    if expiresDelta:
        expire = datetime.now(timezone.utc) + expiresDelta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    encode.update({"exp": expire})
    encodedJWT = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)
    return encodedJWT

#Rutas de autenticación
@app.post("/register")
def register(user: User):
    if user.username in usersDB:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashedPassword = getPasswordHash(user.password)
    usersDB[user.username] = {"username": user.username, "password": hashedPassword}
    return {"msg": "User registered successfully"}

@app.post("/token", response_model=Token)
async def login_access_token(data: OAuth2PasswordRequestForm = Depends()):
    user = authenticateUser(usersDB, data.username, data.password)
    if not user:
        raise HTTPException(
            status_code=400, detail="Incorrect username or password"
        )
    accessTokenExp = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    accessToken = createAccessToken(
        data={"sub": user.username}, expiresDelta=accessTokenExp
    )
    return {"accessToken": accessToken, "tokenType": "bearer"}

#Modelos y rutas de eventos
class Event(BaseModel):
    id: int
    title: str
    description: str
    eventDate: datetime
    notes: List[str] = []
    wasRealized: bool = False

eventsDB = []

#Crear nuevo evento
@app.post("/events/")
def create_event(event: Event, token: str = Depends(oauth2Scheme)):
    eventsDB.append(event)
    return {"msg": "Event created successfully", "event": event}

#Listar todos los eventos
@app.get("/events/")
def get_events(token: str = Depends(oauth2Scheme)):
    return eventsDB

#Filtrar evento por ID
@app.get("/events/{eventID}")
def get_event(eventID: int, token: str = Depends(oauth2Scheme)):
    event = next((event for event in eventsDB if event.id == eventID), None)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

#Actualizar evento
@app.put("/events/{eventID}")
def update_event(eventID: int, updatedEvent: Event, token: str = Depends(oauth2Scheme)):
    for index, event in enumerate(eventsDB):
        if event.id == eventID:
            eventsDB[index] = updatedEvent
            return {"msg": "Event updated successfully", "event": updatedEvent}
    raise HTTPException(status_code=404, detail="Event not found")

#Eliminar evento
@app.delete("/events/{eventID}")
def delete_event(eventID: int, token: str = Depends(oauth2Scheme)):
    print(f"Current events: {[event.id for event in eventsDB]}")
    for index, event in enumerate(eventsDB):
        if event.id == eventID:
            if event.wasRealized:
                raise HTTPException(status_code=400, detail="Cannot delete event")
            del eventsDB[index]
            return {"msg": "Event deleted successfully"}
    raise HTTPException(status_code=404, detail="Event not found")

#Agregar notas a un evento
@app.post("/events/{eventID}/notes")
def add_note_to_event(eventID: int, note: str, token: str = Depends(oauth2Scheme)):
    for event in eventsDB:
        if event.id == eventID:
            event.notes.append(note)
            return {"msg": "Note added successfully", "event": event}
    raise HTTPException(status_code=404, detail="Event not found")

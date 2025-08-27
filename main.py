# Instale as dependências com:
# pip install "fastapi[all]" passlib[bcrypt] sqlalchemy psycopg2-binary python-jose[cryptography]

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from typing import List
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os

# --- Configuração do Banco de Dados ---
# A URL do banco virá de uma variável de ambiente para segurança
DATABASE_URL = "postgresql://neondb_owner:npg_9leQDb6mqxGF@ep-soft-surf-acmo2agy-pooler.sa-east-1.aws.neon.tech/neondb?sslmode=require"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Modelos SQLAlchemy (Tabelas) ---
class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    senha_hash = Column(String, nullable=False)
    tarefas = relationship("TarefaDB", back_populates="dono", cascade="all, delete-orphan")

class TarefaDB(Base):
    __tablename__ = "tarefas"
    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String, index=True, nullable=False)
    descricao = Column(String, nullable=True)
    concluida = Column(Boolean, default=False)
    id_usuario = Column(Integer, ForeignKey("usuarios.id"), nullable=False)
    dono = relationship("UsuarioDB", back_populates="tarefas")

# Cria as tabelas no banco de dados (se não existirem)
Base.metadata.create_all(bind=engine)

# --- Esquemas Pydantic (Validação de Dados) ---
class TarefaBase(BaseModel):
    titulo: str
    descricao: str | None = None

class TarefaCreate(TarefaBase):
    pass

class Tarefa(TarefaBase):
    id: int
    concluida: bool
    class Config:
        orm_mode = True

class UsuarioCreate(BaseModel):
    email: str
    senha: str

class Usuario(BaseModel):
    id: int
    email: str
    class Config:
        orm_mode = True

# --- Segurança e Autenticação ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

SECRET_KEY = os.getenv("SECRET_KEY", "uma_chave_secreta_muito_longa_e_segura")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def verificar_senha(senha_plana, senha_hash):
    return pwd_context.verify(senha_plana, senha_hash)

def get_hash_senha(senha):
    return pwd_context.hash(senha)

def criar_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Dependências ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_usuario_atual(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    usuario = db.query(UsuarioDB).filter(UsuarioDB.email == email).first()
    if usuario is None:
        raise credentials_exception
    return usuario

# --- Inicialização da API ---
app = FastAPI(title="API de Tarefas", description="Uma API para gerenciar sua lista de tarefas.")

# --- Rotas da API ---

# Rota de Autenticação
@app.post("/auth/registrar", response_model=Usuario, status_code=status.HTTP_201_CREATED)
def registrar_usuario(usuario: UsuarioCreate, db: Session = Depends(get_db)):
    db_usuario = db.query(UsuarioDB).filter(UsuarioDB.email == usuario.email).first()
    if db_usuario:
        raise HTTPException(status_code=400, detail="Email já registrado")
    senha_hash = get_hash_senha(usuario.senha)
    novo_usuario = UsuarioDB(email=usuario.email, senha_hash=senha_hash)
    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    return novo_usuario

@app.post("/auth/token")
def login_para_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    usuario = db.query(UsuarioDB).filter(UsuarioDB.email == form_data.username).first()
    if not usuario or not verificar_senha(form_data.password, usuario.senha_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = criar_access_token(data={"sub": usuario.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Rotas de Tarefas
@app.post("/tarefas/", response_model=Tarefa, status_code=status.HTTP_201_CREATED)
def criar_tarefa(tarefa: TarefaCreate, db: Session = Depends(get_db), usuario_atual: UsuarioDB = Depends(get_usuario_atual)):
    nova_tarefa = TarefaDB(**tarefa.dict(), id_usuario=usuario_atual.id)
    db.add(nova_tarefa)
    db.commit()
    db.refresh(nova_tarefa)
    return nova_tarefa

@app.get("/tarefas/", response_model=List[Tarefa])
def listar_tarefas(db: Session = Depends(get_db), usuario_atual: UsuarioDB = Depends(get_usuario_atual)):
    return db.query(TarefaDB).filter(TarefaDB.id_usuario == usuario_atual.id).all()

@app.get("/tarefas/{id_tarefa}", response_model=Tarefa)
def obter_tarefa(id_tarefa: int, db: Session = Depends(get_db), usuario_atual: UsuarioDB = Depends(get_usuario_atual)):
    tarefa = db.query(TarefaDB).filter(TarefaDB.id == id_tarefa, TarefaDB.id_usuario == usuario_atual.id).first()
    if tarefa is None:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada")
    return tarefa

@app.put("/tarefas/{id_tarefa}", response_model=Tarefa)
def atualizar_tarefa(id_tarefa: int, tarefa_atualizada: TarefaCreate, db: Session = Depends(get_db), usuario_atual: UsuarioDB = Depends(get_usuario_atual)):
    tarefa = db.query(TarefaDB).filter(TarefaDB.id == id_tarefa, TarefaDB.id_usuario == usuario_atual.id).first()
    if tarefa is None:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada")
    tarefa.titulo = tarefa_atualizada.titulo
    tarefa.descricao = tarefa_atualizada.descricao
    db.commit()
    db.refresh(tarefa)
    return tarefa

@app.delete("/tarefas/{id_tarefa}", status_code=status.HTTP_204_NO_CONTENT)
def deletar_tarefa(id_tarefa: int, db: Session = Depends(get_db), usuario_atual: UsuarioDB = Depends(get_usuario_atual)):
    tarefa = db.query(TarefaDB).filter(TarefaDB.id == id_tarefa, TarefaDB.id_usuario == usuario_atual.id).first()
    if tarefa is None:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada")
    db.delete(tarefa)
    db.commit()

    return

# models.py

from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

engine = create_engine('sqlite:///chat.db', echo=False)
Base = declarative_base()

class Utilizatori(Base):
    __tablename__ = 'Utilizatori'
    id_utilizator = Column(Integer, primary_key=True)
    nume_utilizator = Column(String, unique=True, nullable=False)
    parola = Column(String, nullable=False)        # hashed password
    rol = Column(String, default='user')           # "user" or "admin"
    data_inregistrare = Column(DateTime, default=datetime.utcnow)
    blocked = Column(Boolean, default=False)

    # Relationship examples:
    mesaje = relationship("Mesaje", back_populates="utilizator")   # one-to-many
    notificari = relationship("Notificari", back_populates="utilizator")
    userchatrooms = relationship("UserChatRoom", back_populates="utilizator")

class CamereDeChat(Base):
    __tablename__ = 'CamereDeChat'
    id_camera = Column(Integer, primary_key=True)
    nume_camera = Column(String, unique=True, nullable=False)
    descriere = Column(String, nullable=True)
    data_creare = Column(DateTime, default=datetime.utcnow)
    creator_id = Column(Integer, ForeignKey('Utilizatori.id_utilizator'))

    # Relationship
    mesaje = relationship("Mesaje", back_populates="camera")
    userchatrooms = relationship("UserChatRoom", back_populates="camera")

class Mesaje(Base):
    __tablename__ = 'Mesaje'
    id_mesaj = Column(Integer, primary_key=True)
    id_utilizator = Column(Integer, ForeignKey('Utilizatori.id_utilizator'), nullable=False)
    id_camera = Column(Integer, ForeignKey('CamereDeChat.id_camera'), nullable=True)
    text_mesaj = Column(String, nullable=False)
    tip_mesaj = Column(String, default="public")   # e.g. "public", "private", ...
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationship
    utilizator = relationship("Utilizatori", back_populates="mesaje")
    camera = relationship("CamereDeChat", back_populates="mesaje")

class Notificari(Base):
    __tablename__ = 'Notificari'
    id_notificare = Column(Integer, primary_key=True)
    id_utilizator = Column(Integer, ForeignKey('Utilizatori.id_utilizator'))
    tip_notificare = Column(String, default="generic")
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationship
    utilizator = relationship("Utilizatori", back_populates="notificari")

class UserChatRoom(Base):
    __tablename__ = 'UserChatRoom'
    id_utilizator = Column(Integer, ForeignKey('Utilizatori.id_utilizator'), primary_key=True)
    id_camera = Column(Integer, ForeignKey('CamereDeChat.id_camera'), primary_key=True)
    data_inregistrare = Column(DateTime, default=datetime.utcnow)

    # Relationship
    utilizator = relationship("Utilizatori", back_populates="userchatrooms")
    camera = relationship("CamereDeChat", back_populates="userchatrooms")

# Create tables
Base.metadata.create_all(engine)

SessionLocal = sessionmaker(bind=engine)
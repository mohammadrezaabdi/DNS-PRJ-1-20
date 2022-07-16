from sqlalchemy import Column, Integer, String, ForeignKey, BINARY, Enum
from sqlalchemy.orm import relationship
import enum
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    firstname = Column(String, unique=False, index=True)
    lastname = Column(String, unique=False, index=True)
    password = Column(String)


class Access(enum.Enum):
    read = 'r'
    read_write = 'rw'

class Type(enum.Enum):
    file = 'file'
    directory = 'dir'


class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=False, index=True)
    path = Column(String, unique=False, index=True)
    hash = Column(BINARY)
    entity_type = Column(Enum(Type))
    owner_key = Column(BINARY)
    owner_id = Column(Integer, ForeignKey("users.id"))
    
    owner = relationship("User", foreign_keys=[owner_id])
    

class ACL(Base):
    __tablename__ = "access_list"

    entity_id = Column(Integer, ForeignKey("entities.id"), primary_key=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True, nullable=False, index=True)
    access = Column(Enum(Access))
    share_key = Column(BINARY)

    entity = relationship("Entity", foreign_keys=[entity_id])
    users = relationship("User", foreign_keys=[user_id])

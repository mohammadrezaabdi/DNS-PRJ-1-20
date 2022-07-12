from sqlalchemy import Column, Integer, String, ForeignKey, BINARY, Enum
from sqlalchemy.orm import relationship
import enum
from database import Base


class Access(enum.Enum):
    read = 'r'
    read_write = 'rw'


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=False, index=True)
    path = Column(String, unique=False, index=True)
    owner_key = Column(BINARY)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User",  foreign_keys=[owner_id])


class FACL(Base):
    __tablename__ = "file_access_list"

    file_id = Column(Integer, ForeignKey("files.id"), primary_key=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True, nullable=False, index=True)
    access = Column(Enum(Access))

    file = relationship("File", foreign_keys=[file_id])
    users = relationship("User", foreign_keys=[user_id])

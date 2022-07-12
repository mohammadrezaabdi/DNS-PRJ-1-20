from sqlalchemy import Column, Integer, String, BINARY

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    firstname = Column(String, unique=False, index=True)
    lastname = Column(String, unique=False, index=True)
    password = Column(String)
    pub_key = Column(BINARY)

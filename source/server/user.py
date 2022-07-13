import binascii
import hashlib

from sqlalchemy import Column, Integer, String, BINARY
import logging
from database import Base
from sqlalchemy.orm import Session
import consts


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    firstname = Column(String, unique=False, index=True)
    lastname = Column(String, unique=False, index=True)
    password = Column(String)
    pubkey = Column(BINARY)


def create_user(db: Session, uid: int, firstname: str, lastname: str, user_pubkey, password: str):
    hashed_password = hashlib.sha256(password.encode('ascii')).digest()
    hashed_password = binascii.hexlify(hashed_password).decode('ascii')
    query = db.query(User).filter_by(id=uid)
    if db.connection().execute(query):
        raise Exception(consts.user_duplication_error)
    db_user = User(id=uid, firstname=firstname, lastname=lastname, password=hashed_password, pubkey=user_pubkey)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

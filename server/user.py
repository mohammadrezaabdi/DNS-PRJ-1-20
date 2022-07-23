import binascii
import hashlib

from Crypto.PublicKey.RSA import RsaKey

from database import get_db
import consts
from model import User


def create_user(uid: int, firstname: str, lastname: str, password: str, pub_key: bytes):
    db = next(get_db())
    hashed_password = hashlib.sha256(password.encode('utf-8')).digest()
    hashed_password = binascii.hexlify(hashed_password).decode('utf-8')
    if db.query(User).filter(User.id == uid).first():
        raise Exception(consts.user_duplication_error)
    db_user = User(id=uid, firstname=firstname, lastname=lastname, password=hashed_password, pub_key=pub_key)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user(uid: int) -> User:
    db = next(get_db())
    return db.query(User).filter(User.id == uid).first()


def authenticate(user: User, password: str):
    hashed_password = hashlib.sha256(password.encode('utf-8')).digest()
    hashed_password = binascii.hexlify(hashed_password).decode('utf-8')
    if hashed_password != user.password:
        raise Exception(consts.incorrect_password)

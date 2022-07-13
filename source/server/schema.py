from pydantic import BaseModel
import enum


class User(BaseModel):
    id: int
    firstname: str
    lastname: str
    password: str
    pubkey: bytes = None

    class Config:
        orm_mode = True


class Access(str, enum.Enum):
    read = 'r'
    read_write = 'rw'


class File(BaseModel):
    id: int
    name: str
    path: str
    hash: bytes
    owner_key: bytes
    owner_id: int

    class Config:
        orm_mode = True


class FACL(BaseModel):
    file_id: int
    user_id: int
    access: Access

    class Config:
        orm_mode = True
        use_enum_values = True

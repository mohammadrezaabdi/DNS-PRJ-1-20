from pydantic import BaseModel
import enum


class User(BaseModel):
    id: int
    firstname: str
    lastname: str
    password: str

    class Config:
        orm_mode = True


class Access(str, enum.Enum):
    read = 'r'
    read_write = 'rw'


class Type(str, enum.Enum):
    file = 'file'
    directory = 'dir'


class Entity(BaseModel):
    id: int
    name: str
    path: str
    hash: bytes
    owner_key: bytes
    entity_type: Type
    owner_id: int

    class Config:
        orm_mode = True
        use_enum_values = True


class ACL(BaseModel):
    entity_id: int
    user_id: int
    access: Access
    share_key: bytes

    class Config:
        orm_mode = True
        use_enum_values = True

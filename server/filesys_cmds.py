import base64
import json
from operator import and_, or_

from munch import DefaultMunch

from common.utils import sha256sum
from database import get_db
from model import Entity, Type, ACL, Access
from session import Session
from sqlalchemy import or_, and_
import fsspec

with open('config.json') as f:
    conf = json.load(f)

FILE_SYSTEM = DefaultMunch.fromDict(conf['filesystem'])
ROOT_PATH = FILE_SYSTEM.ROOT_PATH
fs = fsspec.filesystem('file')


def mkdir_handler(args: list[str], session: Session) -> str:
    # db = next(get_db())
    # results = db.query(Entity).filter().all()
    # for r in results:
    #     print("\n", str(r.id) , r.path,r.name)
    # return
    if len(args) != 1:
        return "Incorrect args!"
    path = args[0]
    parents = path.split("/")
    parents[0] = "/"
    if len(parents) == 1:
        return "Incorrect path: '/'"
    print(parents)
    for i in range(2, len(parents)):
        print(mkdir('/' + '/'.join(parents[1:i]), session=session))
    return mkdir('/' + '/'.join(parents[1:]), session=session)


def mkdir(path: str, session: Session) -> str:
    path = get_absolute_path(path, session)

    name = path.split("/")[-1]
    path = '/'.join(path.split("/")[:-1])
    path = path if path != "" else "/"

    db = next(get_db())
    entity: Entity = db.query(Entity).filter(
        Entity.path == path, Entity.name == name).first()
    if entity:
        if db.query(ACL).filter(ACL.entity_id == entity.id and ACL.user_id == session.user).first():
            return "Directory Exists"
        db_acl = ACL(entity_id=entity.id, user_id=session.user.id,
                     access=Access.read_write, share_key=b'10')
        db.add(db_acl)
        db.commit()
        db.refresh(db_acl)
        return ls_handler([], session)

    db_entity = Entity(name=name, path=path, hash=b'10',
                       entity_type=Type.directory, owner_key=b'10', owner_id=0)
    db.add(db_entity)
    db.commit()
    db.refresh(db_entity)

    db_acl = ACL(entity_id=db_entity.id, user_id=session.user.id,
                 access=Access.read_write, share_key=b'10')
    db.add(db_acl)
    db.commit()
    db.refresh(db_acl)

    return ls_handler([], session)


def rm_handler(args: list[str], session: Session) -> str:
    if not len(args) in (1, 2):
        return "Incorrect args!"
    path: str
    if len(args) == 2 and args[0] == '-r':
        path = args[1]
    elif len(args) == 1:
        path = args[0]
    else:
        return "Improper format"
    path = get_absolute_path(path, session)

    name = path.split("/")[-1]
    path = '/'.join(path.split("/")[:-1])
    path = path if path != "" else "/"
    db = next(get_db())
    print(path)
    result = db.query(ACL).join(Entity).filter(
        or_((and_(Entity.name == name, Entity.path == path)), (
            (and_(Entity.path.like(path + "/" + name), Entity.path != path)))
            ),
        # Entity.entity_type == type_,
        ACL.user_id == session.user.id,
        ACL.entity_id == Entity.id
    ).all()
    for r in result:
        db.query(ACL).filter(
            ACL.entity_id == r.entity_id,
            ACL.user_id == r.user_id,
        ).delete()
    db.commit()
    return "Done"


def cd_handler(args: list[str], session: Session) -> str:
    if len(args) != 1:
        return "Incorrect args!"
    path = get_absolute_path(args[0], session)
    if check_path_for_user(path, session):
        session.current_path = path
        return (f"current path: {path}")
    return "Directory does NOT exist. cd failed."


def get_absolute_path(path: str, session: Session):
    path_list = path.split("/")
    path = session.current_path if path[0] != '/' and session.current_path != "/" else ''
    for p in range(len(path_list)):
        temp = str(path_list[p])
        if temp == '':
            path += "/"
        elif temp == '.':
            continue
        elif temp == '..':
            temp_list = path.split("/")
            print(temp_list)
            # temp_list = temp_list[:p-1]+temp_list[p+1:]
            temp_list = temp_list[:-1]
            path = '/'.join(temp_list)
            print(path)
            continue
        else:
            path += "/" + temp
    path = "/" if path == "" else path
    i = 0
    while i < len(path) - 1:
        if path[i] == "/" and path[i + 1] == "/":
            path = path[:i] + path[i + 1:]
            i -= 1
        i += 1
    return path


def check_path_for_user(path, session: Session):
    db = next(get_db())
    if db.query(Entity, ACL).filter(
            Entity.path == path,
            ACL.user_id == session.user.id,
            ACL.entity_id == Entity.id
    ).first():
        return True
    return False


def ls_handler(args: list[str], session: Session) -> str:
    if len(args) > 1:
        return "Incorrect args!"
    path = args[0] if len(args) == 1 else session.current_path
    db = next(get_db())

    path = get_absolute_path(path, session)
    print("path is ", path)
    result = db.query(Entity, ACL).filter(
        Entity.path == path,
        ACL.user_id == session.user.id,
        ACL.entity_id == Entity.id
    ).all()
    ent_list = ""
    for r in result:
        if r[0].entity_type == Type.directory:
            ent_list += r[0].name + "[d] "
        elif r[0].entity_type == Type.file:
            ent_list += r[0].name + "[f] "
    return ent_list


def touch_handler(args: list[str], session: Session) -> str:
    global fs
    path = args[0] if args[0] else '/'
    file_name = base64.b64decode(args[1])
    file_key = base64.b64decode(args[2])
    file_path = ROOT_PATH + args[1]

    # todo check file and path exists before
    # todo create path if necessary

    # create file
    fs.touch(file_path)

    # save file to database
    db = next(get_db())
    db_entity = Entity(name=args[1], path=path, hash=sha256sum(file_path),
                       entity_type=Type.file, owner_key=file_key, owner_id=session.user.id)
    db.add(db_entity)
    db.commit()
    db.refresh(db_entity)

    db_acl = ACL(entity_id=db_entity.id, user_id=session.user.id,
                 access=Access.read_write, share_key=file_key)
    db.add(db_acl)
    db.commit()
    db.refresh(db_acl)

    return 'file created successfully'


def vim_handler(args: list[str], session: Session) -> str:
    # todo check hash
    # todo check file not exists
    # todo check user have access
    pass

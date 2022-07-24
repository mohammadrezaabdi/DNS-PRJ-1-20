from consts import *
import base64
import json
from operator import and_, or_
import consts
from munch import DefaultMunch
from socket import socket
# from common.utils import *
# from common.consts import *
from database import get_db
from model import Entity, Type, ACL, Access, User
from user import get_user
from session import Session
from sqlalchemy import or_, and_
import fsspec
import sys
sys.path.append('../common')
from utils import *

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
    for i in range(2, len(parents)):
        print(mkdir('/' + '/'.join(parents[1:i]), session=session))
    return mkdir('/' + '/'.join(parents[1:]), session=session)


def mkdir(path: str, session: Session) -> str:
    path = get_absolute_path(path, session)

    name = path.split("/")[-1]
    if name == '':
        return
    path = '/'.join(path.split("/")[:-1])
    path = path if path != "" else "/"

    db = next(get_db())
    entity: Entity = db.query(Entity).filter(
        Entity.path == path, Entity.name == name).first()
    if entity:
        if db.query(ACL).filter(ACL.entity_id == entity.id and ACL.user_id == session.user.id).first():
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


# todo rm file with fsspec
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


# todo show file different from path (by adding /)
def ls_handler(args: list[str], session: Session) -> str:
    if len(args) > 1:
        return "Incorrect args!"
    path = args[0] if len(args) == 1 else session.current_path
    db = next(get_db())

    path = get_absolute_path(path, session)
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


def share_handler(args: list[str], session: Session, conn: socket, server_key_pair: RsaKey) -> str:
    if len(args) != 2:
        msg = str(consts.packet_delimiter_str.join(
            ['0', "Incorrect args!"]))
        return msg

    path = get_absolute_path(args[0], session)

    name = path.split("/")[-1]
    path = '/'.join(path.split("/")[:-1])
    path = path if path != "" else "/"

    if args[1] == session.user.id:
        msg = str(consts.packet_delimiter_str.join(
            ['0', "Can NOT share anything with yourself!"]))
        return msg

    db = next(get_db())

    entity = db.query(
        Entity
    ).filter(
        Entity.path == path
    ).filter(
        Entity.name == name
    ).filter(
        Entity.entity_type == Type.file
    ).filter(
        Entity.owner_id == session.user.id
    ).first()
    if not entity:
        msg = str(consts.packet_delimiter_str.join(
            ['0', "File does NOT exist!"]))
        return msg

    user = db.query(
        User
    ).filter(
        User.id == args[1]
    ).first()

    if not user:
        msg = str(consts.packet_delimiter_str.join(
            ['0', "User does NOT exist!"]))
        return msg

    packet = consts.packet_delimiter_byte.join(
        ['1', user.pub_key, entity.owner_key])
    secure_send(packet, conn, enc_key=session.session_key,
                signature_key=server_key_pair)

    file_key = secure_receive(
        conn, enc_key=session.session_key, signature_key=session.client_pubkey)

    temp_session = Session()
    temp_session.user = user
    mkdir_handler([path], temp_session)
    acl = ACL(entity_id=entity.id, user_id=temp_session.user.id,
              access=Access.read, share_key=file_key)
    db.add(acl)
    db.commit()
    db.refresh(acl)
    return "Done!"


def revoke_handler(args: list[str], session: Session) -> str:
    if len(args) != 1:
        msg = "Incorrect args!"
        return msg

    path = get_absolute_path(args[0], session)

    name = path.split("/")[-1]
    path = '/'.join(path.split("/")[:-1])
    path = path if path != "" else "/"

    db = next(get_db())

    entity = db.query(
        Entity
    ).filter(
        Entity.path == path
    ).filter(
        Entity.name == name
    ).filter(
        Entity.entity_type == Type.file
    ).filter(
        Entity.owner_id == session.user.id
    ).first()
    if not entity:
        msg = "File does NOT exist!"
        return msg

    db.query(
        ACL
    ).filter(
        ACL.entity_id == entity.id
    ).filter(
        ACL.user_id != session.user.id
    ).delete()

    db.commit()
    return "Done!"

def touch_handler(args: list[str], session: Session) -> str:
    global fs
    db = next(get_db())
    path = args[0] if args[0] else session.current_path
    file_name = args[1]
    file_key = base64.b64decode(args[2])

    # touch | path | filename | encrypted_file_key
    # todo create path if necessary
    # todo handle relative paths

    # check if user created the same file with same path before
    # or another user shared same file with them
    if db.query(
            Entity,
            ACL
    ).filter(
        Entity.path == path
    ).filter(
        Entity.name == file_name
    ).filter(
        Entity.id == ACL.entity_id
    ).filter(
        ACL.user_id == session.user.id
    ).first():
        return "file exists or same file shared with you"

    # create file to database
    file = Entity(name=file_name, path=path, entity_type=Type.file,
                  owner_key=file_key, owner_id=session.user.id)

    # create file in filesystem
    filesys_path = get_filesys_path(file)
    fs.touch(filesys_path)
    file.hash = sha256sum(filesys_path)

    # save file to database
    db.add(file)
    db.commit()
    db.refresh(file)

    # add access list
    acl = ACL(entity_id=file.id, user_id=session.user.id,
              access=Access.read_write, share_key=file_key)
    db.add(acl)
    db.commit()
    db.refresh(acl)

    return "file created successfully"


def vim_handler(args: list[str], session: Session, conn: socket, server_key_pair: RsaKey) -> str:
    # todo check user have access
    # todo handle relative paths
    global fs
    db = next(get_db())
    path = args[0] if args[0] else session.current_path
    file_name = args[1]

    # find file via path
    q = db.query(
        Entity,
        ACL
    ).filter(
        Entity.path == path
    ).filter(
        Entity.name == file_name
    ).filter(
        Entity.id == ACL.entity_id
    ).filter(
        ACL.user_id == session.user.id
    ).first()
    if not q:
        return file_not_exists
    file, acl = q

    # check physical file exists
    filesys_path = get_filesys_path(file)
    if not fs.exists(filesys_path):
        return file_not_exists

    # check file hash
    if file.hash != sha256sum(filesys_path):
        return file_corrupted_err

    # send [access + encryption key + file hash]
    packet = consts.packet_delimiter_byte.join(
        [acl.access.name.encode('utf-8'), acl.share_key, file.hash])
    secure_send(packet, conn, enc_key=session.session_key,
                signature_key=server_key_pair)

    # dummy
    secure_receive(conn, enc_key=session.session_key,
                   signature_key=session.client_pubkey)

    # send encrypted file
    send_file(filesys_path, conn)
    packet = secure_receive(conn, enc_key=session.session_key,
                            signature_key=session.client_pubkey)
    if packet.decode('utf-8') == file_received_corrupted_err:
        return "Try again later"

    if acl.access == Access.read:
        return file_only_read

    # dummy
    secure_send(b'DUMMY', conn, enc_key=session.session_key,
                signature_key=server_key_pair)

    # get hash of file
    new_file_hash = secure_receive(
        conn, enc_key=session.session_key, signature_key=session.client_pubkey)

    # dummy
    secure_send(b'DUMMY', conn, enc_key=session.session_key,
                signature_key=server_key_pair)

    # receive encrypted file
    receive_file(filesys_path, conn)

    if new_file_hash != sha256sum(filesys_path):
        return file_received_corrupted_err

    # update file hash
    file.hash = new_file_hash
    db.commit()
    db.refresh(file)

    return "File updated successfully"


def get_filesys_path(entity: Entity) -> str:
    return ROOT_PATH + sha256hash((entity.path + entity.name + str(entity.owner_id)).encode('utf-8')).decode('utf-8')

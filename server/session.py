from user import *
from socket import socket
import os
import pbkdf2
from Crypto.PublicKey import RSA
import sys
from common.utils import *


class Session:
    def __init__(self):
        self.user: User = None
        self.session_key: bytes = None
        self.client_pubkey: RsaKey = None
        self.current_path: str = "/"


users: dict[int, Session] = {}


def login(session: Session, args: list[str]) -> bytes:
    # check if user exists
    user = get_user(int(args[0]))
    if not user:
        raise Exception(consts.user_not_found)
    # check user password
    authenticate(user, args[1])
    # check public key
    if session.client_pubkey.exportKey().decode('utf-8') != user.pub_key.decode('utf-8'):
        raise Exception(consts.public_key_invalid)
    # add user to logged-in users
    session.user = user
    users[user.id] = session
    # generate session key from client password and random salt
    session.session_key = pbkdf2.PBKDF2(passphrase=user.password, salt=os.urandom(16)).read(32)
    # todo set group and default path
    msg = consts.login_success.format(user.id, "work", session.current_path)
    msg = msg.encode('utf-8') + consts.packet_delimiter_byte + session.session_key
    return msg


def signup(args: list[str], session: Session) -> bytes:
    # create user
    create_user(uid=int(args[0]), firstname=args[1], lastname=args[2], password=args[3],
                pub_key=session.client_pubkey.exportKey())
    # send success message
    return consts.signup_success_msg.encode('utf-8')


def share_pubkeys(session: Session, server_key_pair: RsaKey, conn: socket):
    # client hello packet
    client_pubkey = recvall(conn)
    session.client_pubkey = RSA.importKey(client_pubkey)
    # server hello packet
    conn.sendall(server_key_pair.publickey().exportKey())

from utils import *
from user import *
from socket import socket
import os
import pbkdf2
from Crypto.PublicKey import RSA


class Session:
    def __init__(self):
        self.user = None
        self.session_key = None
        self.client_pubkey = None


users: dict[int, Session] = {}


def login(session: Session, args: [str], server_key_pair: RsaKey, conn: socket):
    try:
        # check if user exists
        user = get_user(args[0])
        if not user:
            raise Exception(consts.user_not_found)
        # check user password
        authenticate(user, args[1])
        # add user to logged-in users
        session.user = user
        users[user.id] = session
        # generate session key from client password and random salt
        session.session_key = pbkdf2.PBKDF2(passphrase=user.password, salt=os.urandom(16)).read(32)
        # todo set group and default path
        msg = consts.login_success.format(user.id, "work", "/")
        msg = msg.encode('ascii') + consts.packet_delimiter_byte + session.session_key

        secure_reply(msg, conn, session.client_pubkey, server_key_pair, args[-1])

    except Exception as e:
        secure_reply(str(e), conn, session.client_pubkey, server_key_pair, args[-1])
        raise e


def signup(session: Session, args: [str], server_key_pair: RsaKey, conn: socket):
    try:
        # create user
        create_user(uid=args[0], firstname=args[1], lastname=args[2], password=args[3])
        # send success message
        secure_reply(consts.signup_success_msg, conn, session.client_pubkey, server_key_pair, args[-1])

    except Exception as e:
        secure_reply(str(e), conn, session.client_pubkey, server_key_pair, args[-1])
        raise e


def share_pubkeys(session: Session, server_key_pair: RsaKey, conn: socket):
    # client hello packet
    client_pubkey = recvall(conn)
    session.client_pubkey = RSA.importKey(client_pubkey)
    # server hello packet
    conn.sendall(server_key_pair.publickey().exportKey())


def server_handshake(session: Session, server_key_pair: RsaKey, conn: socket):
    # get client public key
    if not session.client_pubkey:
        share_pubkeys(session, server_key_pair, conn)

    # get client command packet (login or signup)
    packet = recvall(conn)
    if not packet:
        raise Exception(consts.end_client_connection)

    cmd = secure_receive(packet, enc_key=server_key_pair, sign_key=session.client_pubkey)

    cmd_args = cmd.decode("ascii").split(consts.packet_delimiter_str)
    if consts.LOGIN.match(cmd_args[0]):
        login(session, cmd_args[1:], server_key_pair, conn)
    elif consts.SIGNUP.match(cmd_args[0]):
        signup(session, cmd_args[1:], server_key_pair, conn)
    else:
        raise Exception(consts.unknown_packet_err)

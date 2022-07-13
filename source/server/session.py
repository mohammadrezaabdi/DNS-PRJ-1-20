from utils import *
import log
import logging
from user import User, create_user
from socket import socket
from database import db
import traceback

log.init()
logger = logging.getLogger("client")


class Session:
    def __init__(self, user: User = None):
        self.user = user
        self.session_key = None
        self.client_pubkey = None


sessions = dict[int, Session]


def login(session: Session, args: [str], server_key_pair: RSA, conn: socket):
    pass


def signup(session: Session, args: [str], server_key_pair: RSA, conn: socket):
    try:
        # create user
        user = create_user(db=db, uid=args[0], firstname=args[1], lastname=args[2], password=args[3],
                           user_pubkey=session.client_pubkey.exportKey())
        session.user = user

        msg = consts.signup_success_msg.encode("ascii")
        # add client nonce
        msg += consts.packet_delimiter_byte + args[-1].encode("ascii")
        secure_send(msg.encode("ascii"), conn, enc_key=session.client_pubkey, signature_key=server_key_pair)
    except Exception as e:
        msg = consts.internal_server_error_msg.encode("ascii")
        # add client nonce
        msg += consts.packet_delimiter_byte + args[-1].encode("ascii")
        secure_send(msg.encode("ascii"), conn, enc_key=session.client_pubkey, signature_key=server_key_pair)
        raise e


def share_pubkeys(session: Session, server_key_pair: RSA, conn: socket):
    # client hello packet
    client_pubkey = recvall(conn)
    session.client_pubkey = RSA.importKey(client_pubkey)
    # server hello packet
    conn.sendall(server_key_pair.publickey().exportKey())


def server_handshake(session: Session, server_key_pair: RSA, conn: socket):
    # get client public key
    share_pubkeys(session, server_key_pair, conn)

    # get client command packet (login or signup)
    packet = recvall(conn)
    if not packet:
        return

    cmd = secure_receive(packet, enc_key=server_key_pair, sign_key=session.client_pubkey)

    cmd_args = cmd.decode("ascii").split(consts.packet_delimiter_str)
    if consts.LOGIN.match(cmd_args[0]):
        login(session, cmd_args[1:], server_key_pair, conn)
    elif consts.SIGNUP.match(cmd_args[0]):
        signup(session, cmd_args[1:], server_key_pair, conn)
    else:
        raise Exception(consts.unknown_packet_err)


def handle_client(session: Session, server_key_pair: RSA, conn: socket):
    logger.debug("handling new client")
    with conn:
        try:
            while True:
                if not session.session_key:
                    server_handshake(session, server_key_pair, conn)
                    continue

                packet = recvall(conn)
                if not packet:
                    return

        except Exception as e:
            logger.error(str(e))
            print(traceback.format_exc())
            raise e

        finally:
            if session.user:
                sessions.pop(session.user.id)

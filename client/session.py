import base64
from socket import socket
from typing import Tuple

from Crypto.PublicKey import RSA
import consts
import sys
from common.utils import *


class Session:
    def __init__(self, uid=0):
        self.uid: int = uid
        self.session_key: bytes = None
        self.user_key_pair: RsaKey = None
        self.nonce: str = ''
        self.server_pubkey: RsaKey = None
        self.current_path: str = "/"


def test_aes(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def mkdir_cmd(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


# todo set user current path
def cd_cmd(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def rm_cmd(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def ls_cmd(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def touch_cmd(session: Session, cmd: str, conn: socket) -> str:
    # extract file path and file name
    cmd_args = cmd.split(' ')
    file_path, hashed_file_name = get_hashed_file_name_and_path(session, cmd_args[1])
    # generate encrypt file key
    file_key = Fernet.generate_key()
    # encrypt file key
    encrypted_key = encrypt_rsa(file_key, session.user_key_pair.publickey())
    # create final packet
    encrypted_key_str = str(base64.b64encode(encrypted_key), 'utf-8')
    hashed_file_name_str = str(base64.b64encode(hashed_file_name), 'utf-8')
    final_cmd = ' '.join([cmd_args[0], file_path, hashed_file_name_str, encrypted_key_str])
    response = send_cmd_receive_message(session, final_cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def vim_cmd(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def login(session: Session, cmd: str, conn: socket) -> str:
    """
    user login protocol:
        [client hello] Client -> Server: PU_c
        [server hello] Server -> Client: PU_s
        [client auth] Client -> Server: E(PU_s, cmd || uid || password || N_c || E(PR_c, M))
        [key share] Server -> Client: E(PU_c, msg || K_cs || N_c || E(PR_s, M))
    """
    # send & receive client hello & server hello packets
    try:
        if not session.server_pubkey:
            share_pubkeys(session, conn)
    except ValueError:
        raise Exception(consts.end_connection)

    key_share = send_cmd_receive_message(session, cmd, conn)
    key_share_args = key_share.split(consts.packet_delimiter_byte)
    msg = key_share_args[0].decode('utf-8')

    # set session key
    if consts.login_success.match(msg):
        session.session_key = key_share_args[1]

    # return server message
    return msg


def signup(session: Session, cmd: str, conn: socket) -> str:
    """
    user signup protocol:
        [client hello] Client -> Server: PU_c
        [server hello] Server -> Client: PU_s
        [client reg] Client -> Server: E(PU_s, cmd || uid || firstname || lastname || password || N_c || E(PR_c, M))
        [server alive] Server -> Client: E(PU_c, msg || N_c || E(PR_s, M))
    """
    # send & receive client hello & server hello packets
    try:
        if not session.server_pubkey:
            share_pubkeys(session, conn)
    except ValueError:
        raise Exception(consts.end_connection)

    server_alive = send_cmd_receive_message(session, cmd, conn)
    hello_server_args = server_alive.decode('utf-8').split(consts.packet_delimiter_str)

    # return server message
    return hello_server_args[0]


def secure_send_cmd_with_nonce(session: Session, cmd: str, conn: socket, enc_key: Union[bytes, RsaKey],
                               sign_key: RsaKey):
    # insert delimiter im command args
    packet = consts.packet_delimiter_str.join(cmd.split(' ')).encode('utf-8')
    # add nonce to the packet (Server Availability)
    packet, session.nonce = add_nonce(packet)
    # send encrypted packet to client (Confidentiality, Signature)
    secure_send(packet, conn, enc_key, sign_key)


def send_cmd_receive_message(session: Session, cmd: str, conn: socket) -> bytes:
    if not session.session_key:
        secure_send_cmd_with_nonce(session, cmd, conn, session.server_pubkey, session.user_key_pair)
    else:
        secure_send_cmd_with_nonce(session, cmd, conn, session.session_key, session.user_key_pair)

    if not session.session_key:
        return secure_receive(conn, session.user_key_pair, session.server_pubkey, session.nonce)
    else:
        return secure_receive(conn, session.session_key, session.server_pubkey, session.nonce)


def share_pubkeys(session: Session, conn: socket):
    # client hello packet
    conn.sendall(session.user_key_pair.publickey().exportKey())

    # server hello packet
    server_pubkey = recvall(conn)
    session.server_pubkey = RSA.importKey(server_pubkey)


def get_hashed_file_name_and_path(session: Session, filepath: str) -> Tuple[str, bytes]:
    path_args = filepath.split('/')
    file_name = path_args[-1]
    file_path = '/'.join(path_args[:-1]) if path_args[:-1] else session.current_path
    # hash file name : H(PATH + NAME + USER ID)
    hashed_file_name = sha256hash((file_path + file_name + str(session.uid)).encode('utf-8'))
    return file_path, hashed_file_name

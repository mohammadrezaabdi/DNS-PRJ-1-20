from struct import pack
from consts import *
import base64
import shutil
from subprocess import Popen
from typing import Tuple

import fsspec
from Crypto.PublicKey import RSA
from munch import DefaultMunch

import consts
# import sys
# sys.path.append('../common')
from common.utils import *

with open('config.json') as f:
    conf = json.load(f)

KEY = DefaultMunch.fromDict(conf['keys'])
fs = fsspec.filesystem('file')


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

def mv_cmd(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def ls_cmd(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def share_cmd(session: Session, cmd: str, conn: socket) -> str:
    secure_send_cmd_with_nonce(
        session, cmd, conn, session.session_key, session.user_key_pair)

    packet = secure_receive(conn, enc_key=session.session_key, signature_key=session.server_pubkey)

    packet = packet.split(consts.packet_delimiter_byte)
    if packet[0].decode('utf-8') == '0':
        # Error case
        return packet[1].decode('utf-8')

    target_rsa_key = RSA.import_key(packet[1])
    file_key = decrypt_rsa(packet[2], session.user_key_pair)
    encrypted_file_key = encrypt_rsa(file_key, target_rsa_key)

    secure_send(encrypted_file_key, conn, enc_key=session.session_key, signature_key=session.user_key_pair)

    packet = secure_receive(conn, enc_key=session.session_key, signature_key=session.server_pubkey, nonce=session.nonce)
    res = (packet.split(consts.packet_delimiter_byte)[0].decode('utf-8'))
    return res


def revoke_cmd(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def touch_cmd(session: Session, cmd: str, conn: socket) -> str:
    # extract file path and file name
    cmd_args = cmd.split(' ')
    # file_path, file_name = get_file_name_and_path(session, cmd_args[1])
    # generate encrypt file key
    file_key = Fernet.generate_key()
    # encrypt file key
    encrypted_key = encrypt_rsa(file_key, session.user_key_pair.publickey())
    # create final packet
    encrypted_key_str = str(base64.b64encode(encrypted_key), 'utf-8')
    # final_cmd = ' '.join(
    #     [cmd_args[0], file_path, file_name, encrypted_key_str])
    final_cmd = ' '.join(
        [cmd_args[0], cmd_args[1], encrypted_key_str])
    response = send_cmd_receive_message(session, final_cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('utf-8')
    return msg


def vim_cmd(session: Session, cmd: str, conn: socket.socket) -> str:
    # extract file path and file name
    cmd_args = cmd.split(' ')
    file_path, file_name = get_file_name_and_path(session, cmd_args[1])
    final_cmd = ' '.join([cmd_args[0], cmd_args[1]])
    secure_send_cmd_with_nonce(
        session, final_cmd, conn, session.session_key, session.user_key_pair)
    # get file key and access
    packet = secure_receive(conn, enc_key=session.session_key, signature_key=session.server_pubkey)
    packet_args = packet.split(consts.packet_delimiter_byte)
    msg = packet_args[0].decode('utf-8')
    if msg in [file_not_exists, file_corrupted_err]:
        return msg
    access = msg
    file_key = decrypt_rsa(packet_args[1], session.user_key_pair)
    file_hash = packet_args[2]

    # dummy
    secure_send(b'DUMMY', conn, enc_key=session.session_key,
                signature_key=session.user_key_pair)

    # receive file
    receive_file(file_name, conn)

    # dummy
    secure_send(b'DUMMY', conn, enc_key=session.session_key,
                signature_key=session.user_key_pair)

    # check hash
    if file_hash != sha256sum(file_name):
        secure_send(consts.file_received_corrupted_err.encode('utf-8'), conn, enc_key=session.session_key,
                    signature_key=session.user_key_pair)
        return packet.split(consts.packet_delimiter_byte)[0].decode('utf-8')

    secure_send(consts.file_received_success.encode('utf-8'), conn, enc_key=session.session_key,
                signature_key=session.user_key_pair)

    # decrypt file
    decrypt_file(file_name, file_key)

    # open file in editor
    # return on closing the editor
    open_file_editor(file_name)

    if access == consts.rw:
        # encrypt file
        encrypt_file(file_name, file_key)

        # dummy
        secure_receive(conn, enc_key=session.session_key,
                       signature_key=session.server_pubkey)

        # send hash of edited file
        new_file_hash = sha256sum(file_name)
        secure_send(new_file_hash, conn, enc_key=session.session_key,
                    signature_key=session.user_key_pair)

        # dummy
        secure_receive(conn, enc_key=session.session_key,
                       signature_key=session.server_pubkey)

        # send file
        send_file(file_name, conn)

        # dummy
        secure_receive(conn, enc_key=session.session_key,
                       signature_key=session.server_pubkey)

    # remove temp file
    fs.rm(file_name)

    response = secure_receive(
        conn, session.session_key, session.server_pubkey, session.nonce)
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
    hello_server_args = server_alive.decode(
        'utf-8').split(consts.packet_delimiter_str)

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
        secure_send_cmd_with_nonce(
            session, cmd, conn, session.server_pubkey, session.user_key_pair)
    else:
        secure_send_cmd_with_nonce(
            session, cmd, conn, session.session_key, session.user_key_pair)

    if not session.session_key:
        return secure_receive(conn, session.user_key_pair, session.server_pubkey, session.nonce)
    else:
        return secure_receive(conn, session.session_key, session.server_pubkey, session.nonce)


def share_pubkeys(session: Session, conn: socket):
    # client hello packet
    conn.sendall(session.user_key_pair.publickey().exportKey())

    # server hello packet
    server_pubkey = recvall(conn)
    # check if client knows server
    server_pubkey = RSA.importKey(server_pubkey)
    check_server_public_key(server_pubkey)
    session.server_pubkey = server_pubkey


def get_file_name_and_path(session: Session, filepath: str) -> Tuple[str, str]:
    path_args = filepath.split('/')
    file_name = path_args[-1]
    file_path = '/'.join(path_args[:-1]
                         ) if path_args[:-1] else session.current_path
    return file_path, file_name


# todo is working for windows ?
def open_file_editor(file_name: str):
    if hasattr(os, "startfile"):
        os.startfile(file_name)
    elif shutil.which("vim"):
        Popen(["vim", file_name]).wait()
    elif "EDITOR" in os.environ:
        Popen([os.environ["EDITOR"], file_name]).wait()


def check_server_public_key(server_pubkey: RsaKey):
    path = 'client/' + KEY.KNOWN_KEYS
    # path = './' + KEY.KNOWN_KEYS
    for file in os.listdir(path):
        if file.endswith(".pem"):
            with open(path + file, 'r') as key_file:
                server_key_pair = RSA.import_key(key_file.read())
                if server_key_pair.public_key().export_key().decode('utf-8') \
                        == server_pubkey.export_key().decode('utf-8'):
                    return
    raise Exception(consts.server_unknown)

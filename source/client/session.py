from common.utils import *
from socket import socket
from Crypto.PublicKey import RSA
import consts

class Session:
    def __init__(self, uid=0):
        self.uid = uid
        self.session_key = None
        self.user_key_pair = None
        self.nonce = ''
        self.server_pubkey = None


def test_aes(session: Session, cmd: str, conn: socket) -> str:
    response = send_cmd_receive_message(session, cmd, conn)
    msg = response.split(consts.packet_delimiter_byte)[0].decode('ascii')
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
    if not session.server_pubkey:
        share_pubkeys(session, conn)

    key_share = send_cmd_receive_message(session, cmd, conn)
    key_share_args = key_share.split(consts.packet_delimiter_byte)
    msg = key_share_args[0].decode('ascii')

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
    if not session.server_pubkey:
        share_pubkeys(session, conn)

    server_alive = send_cmd_receive_message(session, cmd, conn)
    hello_server_args = server_alive.decode("ascii").split(consts.packet_delimiter_str)

    # return server message
    return hello_server_args[0]


def secure_send_cmd_with_nonce(session: Session, cmd: str, conn: socket, enc_key: Union[bytes, RsaKey],
                               sign_key: RsaKey):
    # insert delimiter im command args
    packet = consts.packet_delimiter_str.join(cmd.split(' ')).encode('ascii')
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

from utils import *
from socket import socket
from Crypto.PublicKey import RSA


class Session:
    def __init__(self, uid=0):
        self.uid = uid
        self.session_key = None
        self.user_key_pair = None
        self.nonce = ''
        self.server_pubkey = None


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

    # insert delimiter im command args
    cmd = consts.packet_delimiter_str.join(cmd.split(' '))

    # client auth packet
    send_cmd_secure(session, cmd, conn)

    # server live packet
    response_packet = recvall(conn)

    key_share = secure_receive(response_packet, session.user_key_pair, session.server_pubkey, session.nonce)
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

    # insert delimiter im command args
    cmd = consts.packet_delimiter_str.join(cmd.split(' '))

    # client reg packet
    send_cmd_secure(session, cmd, conn)

    # server live packet
    response_packet = recvall(conn)

    server_alive = secure_receive(response_packet, session.user_key_pair, session.server_pubkey, session.nonce)
    hello_server_args = server_alive.decode("ascii").split(consts.packet_delimiter_str)

    # return server message
    return hello_server_args[0]


def send_cmd_secure(session: Session, cmd: str, conn: socket):
    packet = cmd.encode("ascii")
    # add nonce to the packet (Server Availability)
    packet, session.nonce = add_nonce(packet)
    # send encrypted packet to client (Confidentiality, Signature)
    secure_send(packet, conn, session.server_pubkey, session.user_key_pair)


def share_pubkeys(session: Session, conn: socket):
    # client hello packet
    conn.sendall(session.user_key_pair.publickey().exportKey())

    # server hello packet
    server_pubkey = recvall(conn)
    session.server_pubkey = RSA.importKey(server_pubkey)

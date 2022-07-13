from utils import *
from socket import socket
from random import randrange
import sys


class Session:
    def __init__(self, uid=0):
        self.uid = uid
        self.session_key = None
        self.user_key_pair = RSA.generate(3072)
        self.nonce = ''
        self.server_pubkey = None


def login(session: Session, args: [str], conn: socket):
    """
    user login protocol:
        [client hello] Client -> Server: PU_c
        [server hello] Server -> Client: PU_s
        [client auth] Client -> Server: E(PU_s, cmd || uid || password || N_c || E(PR_c, M))
        [key share] Server -> Client: E(PU_c, K_cs || N_c || E(PR_s, M))
    """
    pass


def signup(session: Session, args: [str], conn: socket):
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

    # client auth packet
    # set user id
    session.uid = args[1]
    # generate hello client packet
    client_reg = consts.packet_delimiter_str.join(args)
    client_reg = client_reg.encode("ascii")
    # add nonce to the packet (Server Availability)
    client_reg, session.nonce = add_nonce(client_reg)
    # send encrypted packet to client
    secure_send(client_reg, conn, session.server_pubkey, session.user_key_pair)

    # server live packet
    response_packet = recvall(conn)

    server_alive = secure_receive(response_packet, session.user_key_pair, session.server_pubkey, session.nonce)
    hello_server_args = server_alive.decode("ascii").split(consts.packet_delimiter_str)

    # return server message
    return hello_server_args[0]


def share_pubkeys(session: Session, conn: socket):
    # client hello packet
    conn.sendall(session.user_key_pair.publickey().exportKey())

    # server hello packet
    server_pubkey = recvall(conn)
    session.server_pubkey = RSA.importKey(server_pubkey)


def handle_client_cli(session: Session, conn: socket):
    while True:
        cmd = input().strip()
        if not session.session_key:
            if consts.LOGIN.match(cmd):
                login(session, cmd.split(' '), conn)
            elif consts.SIGNUP.match(cmd):
                msg = signup(session, cmd.split(' '), conn)
                print(msg)
            else:
                raise Exception(consts.unknown_command_err)
            continue
        # todo other commands

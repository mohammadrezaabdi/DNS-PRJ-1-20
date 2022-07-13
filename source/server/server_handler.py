import concurrent.futures
from typing import Callable, Any
import log
import logging
from Crypto.PublicKey import RSA
from session import *
from common.utils import *
import consts
import traceback

log.init()
logger = logging.getLogger("client")


class Server:
    def __init__(self, ip: str, port: str, handler: Callable[[Session, RSA, socket.socket], Any],
                 logger: logging.Logger):
        self.ip = ip
        self.port = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger
        self.handler = handler
        self.key_pair = RSA.generate(3072)

    def listen(self):
        self.logger.info("server process started")
        self.logger.info(f"trying to start listening at {self.ip}:{self.port}")
        with self.sock as s:
            s.bind((self.ip, self.port))
            self.receive_clients()

    def receive_clients(self):
        self.sock.listen()
        self.logger.info("started listening...")
        with concurrent.futures.ThreadPoolExecutor() as thread_pool:
            while True:
                conn, addr = self.sock.accept()
                self.logger.info(f"accepted new client with address {addr}")
                thread_pool.submit(self.handler, Session(), self.key_pair, conn)


def client_authentication(session: Session, server_key_pair: RsaKey, conn: socket):
    # get client public key
    if not session.client_pubkey:
        share_pubkeys(session, server_key_pair, conn)

    # get client command packet (login or signup)
    cmd = secure_receive(enc_key=server_key_pair, sign_key=session.client_pubkey, conn=conn)

    cmd_args = cmd.decode("ascii").split(consts.packet_delimiter_str)
    if consts.LOGIN.match(cmd_args[0]):
        login(session, cmd_args[1:], server_key_pair, conn)
    elif consts.SIGNUP.match(cmd_args[0]):
        signup(session, cmd_args[1:], server_key_pair, conn)
    else:
        raise Exception(consts.unknown_packet_err)


def handle_client(session: Session, server_key_pair: RsaKey, conn: socket):
    logger.debug("handling new client")
    with conn:
        try:
            while True:
                try:
                    if not session.session_key:
                        client_authentication(session, server_key_pair, conn)
                        continue

                    # get command from client securely
                    cmd = secure_receive(enc_key=session.session_key, sign_key=session.client_pubkey, conn=conn)
                    cmd_args = cmd.decode("ascii").split(consts.packet_delimiter_str)
                    # handle client commands
                    if 'test' == cmd_args[0]:
                        msg = 'tested'
                    # todo handle other commands

                    # send message to client
                    secure_reply(msg.encode('ascii'), conn, enc_key=session.session_key, sign_key=server_key_pair,
                                 nonce=cmd_args[-1])

                except Exception as e:
                    if consts.end_connection == str(e):
                        logger.info(str(e))
                        return
                    logger.error(str(e))
                    print(traceback.format_exc())

        finally:
            if session.user:
                users.pop(session.user.id)

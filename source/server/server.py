import concurrent.futures
from typing import Callable, Any
import log
import logging
from Crypto.PublicKey import RSA
from session import Session, server_handshake, users
from utils import *
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


def handle_client(session: Session, server_key_pair: RsaKey, conn: socket):
    logger.debug("handling new client")
    with conn:
        while True:
            try:
                if not session.session_key:
                    server_handshake(session, server_key_pair, conn)
                    continue

                packet = recvall(conn)
                if not packet:
                    raise Exception(consts.end_client_connection)

                # todo handle other commands

            except Exception as e:
                if consts.end_client_connection == str(e):
                    logger.info(str(e))
                    return
                logger.error(str(e))
                print(traceback.format_exc())

            finally:
                if session.user:
                    users.pop(session.user.id)

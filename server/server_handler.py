import concurrent.futures
import re
from typing import Callable, Any
import log
import logging
from Crypto.PublicKey import RSA
from session import *
from filesys_cmds import *
import consts
import traceback
import sys
# sys.path.append('../common')
# from utils import *
from common.utils import *

log.init()
logger = logging.getLogger("client")


class Server:
    def __init__(self, ip: str, port: str, key: RsaKey, handler: Callable[[Session, RSA.RsaKey, socket.socket], Any],
                 logger: logging.Logger):
        self.ip = ip
        self.port = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger
        self.handler = handler
        self.key_pair = key

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
                session = Session()
                sessions.add(session)
                thread_pool.submit(self.handler, session, self.key_pair, conn)


def client_authentication(session: Session, server_key_pair: RsaKey, conn: socket):
    # get client public key
    try:
        if not session.client_pubkey:
            share_pubkeys(session, server_key_pair, conn)
    except ValueError:
        raise Exception(consts.end_connection)

    # get client command packet (login or signup)
    packet = secure_receive(enc_key=server_key_pair, signature_key=session.client_pubkey, conn=conn)
    cmd_args = packet.decode('utf-8').split(consts.packet_delimiter_str)
    cmd = ' '.join(cmd_args[:-1])
    logger.info('received command: ' + cmd)
    try:
        if consts.LOGIN.match(cmd):
            msg = login(session, cmd_args[1:-1])
        elif consts.SIGNUP.match(cmd):
            msg = signup(cmd_args[1:-1], session)
        else:
            raise Exception(consts.unknown_packet_err)

        secure_reply(msg, conn, enc_key=session.client_pubkey, sign_key=server_key_pair,
                     nonce=cmd_args[-1])

    except Exception as e:
        secure_reply(str(e).encode('utf-8'), conn, enc_key=session.client_pubkey, sign_key=server_key_pair,
                     nonce=cmd_args[-1])
        raise e


def handle_client(session: Session, server_key_pair: RsaKey, conn: socket):
    logger.debug("handling new client")
    with conn:
        while True:
            try:
                if not session.session_key:
                    client_authentication(session, server_key_pair, conn)
                    continue

                # get command from client securely
                packet = secure_receive(enc_key=session.session_key, signature_key=session.client_pubkey, conn=conn)
                cmd_args = packet.decode('utf-8').split(consts.packet_delimiter_str)
                cmd = ' '.join(cmd_args[:-1])
                logger.info('received command: ' + cmd)
                logger.info(cmd_args)

                # handle client commands
                # todo check REGEX
                if re.compile(r'^test').match(cmd):
                    msg = 'tested'

                elif re.compile(r'^mkdir ').match(cmd):
                    msg = mkdir_handler(cmd_args[1:-1], session)

                elif re.compile(r'^ls').match(cmd):
                    msg = ls_handler(cmd_args[1:-1], session)

                elif re.compile(r'^cd ').match(cmd):
                    msg = cd_handler(cmd_args[1:-1], session)

                elif re.compile(r'^rm ').match(cmd):
                    msg = rm_handler(cmd_args[1:-1], session)
                    
                elif re.compile(r'^mv ').match(cmd):
                    msg = mv_handler(cmd_args[1:-1], session)

                elif re.compile(r'^touch ').match(cmd):
                    msg = touch_handler(cmd_args[1:-1], session)


                elif re.compile(r'^vim ').match(cmd):
                    msg = vim_handler(cmd_args[1:-1], session, conn, server_key_pair)

                elif re.compile(r'^share ').match(cmd):
                    msg = share_handler(cmd_args[1:-1], session, conn, server_key_pair)

                elif re.compile(r'^revoke ').match(cmd):
                    msg = revoke_handler(cmd_args[1:-1], session)

                # send message to client
                secure_reply(msg.encode('utf-8'), conn, enc_key=session.session_key, sign_key=server_key_pair,
                             nonce=cmd_args[-1])

            except Exception as e:
                if consts.end_connection == str(e):
                    logger.info(str(e))
                    return
                logger.error(str(e))
                print(traceback.format_exc())

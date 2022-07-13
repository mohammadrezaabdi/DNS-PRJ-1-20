import logging
from munch import DefaultMunch
from session import *
import socket


def handle_client(session: Session, server: DefaultMunch):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((server.IP, server.PORT))

            print(consts.socket_start_connection_message_msg)
            handle_client_cli(session, s)

        except Exception as e:
            logging.error(str(e))
            raise e


def handle_client_cli(session: Session, conn: socket):
    while True:
        cmd = input().strip()
        if not session.session_key:
            if consts.LOGIN.match(cmd):
                msg = login(session, cmd, conn)
                print(msg)
            elif consts.SIGNUP.match(cmd):
                msg = signup(session, cmd, conn)
                print(msg)
            else:
                raise Exception(consts.unknown_command_err)
            continue
        # todo other commands

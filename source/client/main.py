import logging
import socket
import json
from munch import DefaultMunch
import consts
import session

from session import Session

with open('config.json') as f:
    conf = json.load(f)

SERVER = DefaultMunch.fromDict(conf['server'])


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((SERVER.IP, SERVER.PORT))

            print(consts.socket_start_connection_message_msg)
            session.handle_client_cli(Session(), s)

        except Exception as e:
            logging.error(str(e))
            raise e


if __name__ == "__main__":
    main()

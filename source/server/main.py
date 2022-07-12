import json
import socket
import logging
import log
from server import Server
from cmd_handler import handle_cmd

log.init()
logger = logging.getLogger("server")

with open('config.json') as f:
    conf = json.load(f)

SERVER = conf['server']


def handle_client(conn: socket.socket):
    logger.debug("handling new client")
    with conn:
        try:
            command = conn.recv(SERVER['BUFFER_SIZE']).decode("ascii")
            if not command:
                return

            answer = handle_cmd(command)
            conn.sendall(str(answer).encode("ascii"))

        except Exception as e:
            raise e


def main():
    filesystem_server = Server(SERVER['IP'], SERVER['PORT'], handle_client, logger)
    filesystem_server.listen()


if __name__ == "__main__":
    main()

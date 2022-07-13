import json
import logging
import log
from munch import DefaultMunch
from server import Server
from session import handle_client

log.init()
logger = logging.getLogger("server")

with open('config.json') as f:
    conf = json.load(f)

SERVER = DefaultMunch.fromDict(conf['server'])


def main():
    filesystem_server = Server(SERVER.IP, SERVER.PORT, handle_client, logger)
    filesystem_server.listen()


if __name__ == "__main__":
    main()

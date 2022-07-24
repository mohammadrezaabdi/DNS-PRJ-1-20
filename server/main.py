import json
import logging

from Crypto.PublicKey import RSA

import log
from munch import DefaultMunch
from server_handler import Server, handle_client
from database import engine
import model
import sys

log.init()
logger = logging.getLogger("server")

with open('config.json') as f:
    conf = json.load(f)

SERVER = DefaultMunch.fromDict(conf['server'])
KEY = DefaultMunch.fromDict(conf['keys'])

# create tables
model.Base.metadata.create_all(bind=engine)


def main():
    # get key pairs
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = 'server/' + KEY.DEFAULT_PATH
    with open(str(path), 'r') as key_file:
        server_key_pair = RSA.import_key(key_file.read())
    # start server
    filesystem_server = Server(SERVER.IP, SERVER.PORT, server_key_pair, handle_client, logger)
    filesystem_server.listen()


if __name__ == "__main__":
    main()

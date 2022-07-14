import json
import logging
import log
from munch import DefaultMunch
from server_handler import Server, handle_client
from database import engine
import model

log.init()
logger = logging.getLogger("server")

with open('config.json') as f:
    conf = json.load(f)

SERVER = DefaultMunch.fromDict(conf['server'])

# create tables
model.Base.metadata.create_all(bind=engine)


def main():
    # start server
    filesystem_server = Server(SERVER.IP, SERVER.PORT, handle_client, logger)
    filesystem_server.listen()


if __name__ == "__main__":
    main()

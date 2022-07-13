import json
from munch import DefaultMunch
from client import handle_client
import sys
from Crypto.PublicKey import RSA
from time import gmtime, strftime

from session import Session

with open('config.json') as f:
    conf = json.load(f)

SERVER = DefaultMunch.fromDict(conf['server'])
KEY = DefaultMunch.fromDict(conf['keys'])


def main():
    session = Session()
    if len(sys.argv) > 1:
        with open(str(sys.argv[1]), 'r') as key_file:
            session.user_key_pair = RSA.import_key(key_file.read())
    else:
        # generate keys and save to file
        session.user_key_pair = RSA.generate(3072)
        with open(KEY.DEFAULT_PATH + f'key_{strftime("%Y-%m-%d_%H-%M-%S", gmtime())}' + '.pem', 'wb') as key_file:
            key_file.write(session.user_key_pair.export_key('PEM'))

    handle_client(session, SERVER)


if __name__ == "__main__":
    main()

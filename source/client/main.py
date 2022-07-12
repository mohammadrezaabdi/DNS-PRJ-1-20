import socket
import json

with open('config.json') as f:
    conf = json.load(f)

SERVER = conf['server']


def network_init():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER['IP'], SERVER['PORT']))

        message = input()
        s.sendall(message.encode("ascii"))

        response = s.recv(SERVER['BUFFER_SIZE']).decode("ascii")
        print(response)
        return


def main():
    network_init()


if __name__ == "__main__":
    main()

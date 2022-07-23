import logging
import re
import traceback
from munch import DefaultMunch
from session import *
import socket
import consts


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
        try:
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

            cmd = ' '.join(cmd.split())
            # todo check regex
            if re.compile('test').match(cmd):
                print(test_aes(session, cmd, conn))
            
            elif re.compile('^mkdir ').match(cmd):
                print(mkdir_cmd(session, cmd, conn))
            
            elif re.compile('^ls').match(cmd):
                print(ls_cmd(session, cmd, conn))
            
            elif re.compile('^cd ').match(cmd):
                print(cd_cmd(session, cmd, conn))
            
            elif re.compile('^rm ').match(cmd):
                print(rm_cmd(session, cmd, conn))

            elif re.compile('^touch ').match(cmd):
                print(touch_cmd(session, cmd, conn))

            elif re.compile('^vim ').match(cmd):
                print(vim_cmd(session, cmd, conn))
            # todo other commands

        except EOFError:
            return
        except Exception as e:
            if consts.end_connection == str(e):
                print(str(e))
                return
            logging.error(str(e))
            print(traceback.format_exc())

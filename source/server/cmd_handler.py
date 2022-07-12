import re


def handle_cmd(cmd):
    print(cmd)
    if re.match(r'hello', cmd):
        return 'client said hello'

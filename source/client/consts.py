import re

packet_delimiter_str = '\0\0'
packet_delimiter_byte = b'\0\0'

# commands
LOGIN = re.compile(r'^login\s+\d+\s+[\w\W]+')
SIGNUP = re.compile(r'^signup\s+\d+\s+\w+\s+\w+\s+[\w\W]+')

# messages
socket_start_connection_message_msg = "you've connected successfully to server\nnow you can login or signup."

unknown_command_err = 'unknown command'

packet_corrupted_err = 'received packet is not valid'
nonce_not_match_error = 'received packet is not from current session'

import re

packet_delimiter_str = '\0\0'
packet_delimiter_byte = b'\0\0'
EOF = b'\0EOF\0'
rw = 'read_write'
# commands
LOGIN = re.compile(r'^login\s+\d+\s+[\w\W]+')
SIGNUP = re.compile(r'^signup\s+\d+\s+\w+\s+\w+\s+[\w\W]+')

# messages
socket_start_connection_message_msg = "you've connected successfully to server\nnow you can login or signup."

unknown_command_err = 'unknown command'
login_success = re.compile(r"^you've successfully logged in\.\nuser id: \d+\ngroup: [\w\W]+\ncurrent path: .*")
packet_corrupted_err = 'received packet is not valid'
nonce_not_match_error = 'received packet is not from current session'
end_connection = 'connection closed'
file_corrupted_err = 'file was corrupted'
file_received_corrupted_err = 'file received corrupted'
file_received_success = 'file received successfully'
file_only_read = "NOTICE: You can't Modify this file"
file_not_exists = "No such file or directory"

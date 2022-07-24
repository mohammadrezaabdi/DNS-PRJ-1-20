import re

packet_delimiter_str = '\0\0'
packet_delimiter_byte = b'\0\0'
EOF = b'\0EOF\0'

# commands
LOGIN = re.compile(r'^login\s+\d+\s+[\w\W]+')
SIGNUP = re.compile(r'^signup\s+\d+\s+\w+\s+\w+\s+[\w\W]+')
# messages
login_success = "you've successfully logged in.\nuser id: {}\ngroup: {}\ncurrent path: {}"
user_duplication_error = "user was duplicated."
user_not_found = "user not found"
incorrect_password = "incorrect password"
signup_success_msg = "user created successfully."
internal_server_error_msg = "cannot operate your command successfully."
unknown_packet_err = 'unknown packet received'
end_connection = 'connection closed'
packet_corrupted_err = 'received packet is not valid'
nonce_not_match_error = 'received packet is not from current session'
file_corrupted_err = 'file was corrupted'
file_received_corrupted_err = 'file received corrupted'
file_received_success = 'file received successfully'
file_only_read = "NOTICE: You can't Modify this file"
file_not_exists = "No such file or directory"

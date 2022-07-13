import re

packet_delimiter_str = '\0'
packet_delimiter_byte = b'\0\0'

# commands
LOGIN = re.compile(r'^login')
SIGNUP = re.compile(r'^signup')

# messages
user_duplication_error = "user was duplicated."
signup_success_msg = "user created successfully."
internal_server_error_msg = "cannot operate you command successfully."
unknown_packet_err = 'unknown packet received'

packet_corrupted_err = 'received packet is not valid'
nonce_not_match_error = 'received packet is not from current session'

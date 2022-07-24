# delimiters
import re

packet_delimiter_str = '\0\0'
packet_delimiter_byte = b'\0\0'
EOF = b'\0EOF\0'

# messages
end_connection = 'connection closed'
nonce_not_match_error = 'received packet is not from current session'
packet_corrupted_err = 'received packet is not valid'
file_corrupted_err = 'file was corrupted'
file_received_corrupted_err = 'file received corrupted'
file_received_success = 'file received successfully'
file_only_read = "NOTICE: You can't Modify this file"
file_not_exists = "No such file or directory"

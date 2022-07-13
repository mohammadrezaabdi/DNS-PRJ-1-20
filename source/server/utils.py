from Crypto.Random import get_random_bytes
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
import json
from random import randrange
import sys
import consts
import funcy
import socket
from typing import Union

with open('config.json') as f:
    conf = json.load(f)

BUFF_SIZE = conf['server']['BUFFER_SIZE']


def recvall(sock):
    return sock.recv(BUFF_SIZE)


def sign_packet(packet: bytes, signature_key: RsaKey) -> bytes:
    # calculate hash of the packet (Validation)
    msg_hash = SHA256.new(packet)
    # calculate the signature from keys (Signature)
    signer = PKCS115_SigScheme(signature_key)
    signature = signer.sign(msg_hash)
    # add hash to the packet
    packet += consts.packet_delimiter_byte + signature
    return packet


def check_signature(packet: bytes, sign_key: RsaKey):
    # calculate and check packet hash (Signature, Confidentiality)
    packet_args = packet.split(consts.packet_delimiter_byte)
    signature = packet_args[-1]
    msg_hash = SHA256.new(consts.packet_delimiter_byte.join(packet_args[:-1]))
    signer = PKCS115_SigScheme(sign_key)
    try:
        signer.verify(msg_hash, signature)
    except:
        raise Exception(consts.packet_corrupted_err)


def add_nonce(packet: bytes) -> tuple[bytes, str]:
    # add nonce to the packet (Availability)
    nonce = randrange(sys.maxsize)
    packet += consts.packet_delimiter_byte + str(nonce).encode('ascii')
    return packet, str(nonce)


def check_nonce(packet: bytes, nonce: str):
    # the last bytes of packet should be nonce
    packet_nonce = packet.split(consts.packet_delimiter_byte)[-1]
    if packet_nonce.decode('ascii') != nonce:
        raise Exception(consts.nonce_not_match_error)


def encrypt_rsa(packet: bytes, enc_key: RsaKey):
    chunks = list(funcy.chunks(enc_key.size_in_bytes() - 11, packet))
    # encrypt all chunks with rsa key (ECB mode)
    encryptor = PKCS1_v1_5.new(enc_key)
    encrypted_packet = b''
    for chunk in chunks:
        encrypted_packet += encryptor.encrypt(chunk)
    return encrypted_packet


def decrypt_rsa(packet: bytes, dec_key: RsaKey):
    chunks = list(funcy.chunks(dec_key.size_in_bytes(), packet))
    # decrypt all chunks with rsa key (ECB mode)
    decryptor = PKCS1_v1_5.new(dec_key)
    sentinel = get_random_bytes(16)
    decrypted_packet = b''
    for chunk in chunks:
        decrypted_packet += decryptor.decrypt(chunk, sentinel)
    return decrypted_packet


def secure_send(packet: bytes, conn: socket.socket, enc_key: Union[RsaKey, bytes], signature_key: RsaKey = None):
    if signature_key is not None:
        packet = sign_packet(packet, signature_key)
    # encrypt packet with public key (Confidentiality)
    if type(enc_key) == RsaKey:
        encrypted_packet = encrypt_rsa(packet, enc_key)
    # send encrypted packet
    conn.sendall(encrypted_packet)


def secure_reply(msg: bytes, conn: socket.socket, enc_key: Union[RsaKey, bytes], server_key_pair: RsaKey,
                 nonce: str = ''):
    # add client nonce
    if nonce:
        msg += consts.packet_delimiter_byte + nonce.encode("ascii")
    secure_send(msg, conn, enc_key=enc_key, signature_key=server_key_pair)


def secure_receive(encrypted_packet: bytes, enc_key: Union[RsaKey, bytes], sign_key: RsaKey = None,
                   nonce: str = '') -> bytes:
    # decrypt packet with private server key
    if type(enc_key) == RsaKey:
        packet = decrypt_rsa(encrypted_packet, enc_key)
    # check signature
    if sign_key is not None:
        check_signature(packet, sign_key)
    # check nonce
    if nonce:
        packet_without_signature = packet
        if sign_key:
            packet_without_signature = consts.packet_delimiter_byte.join(
                packet.split(consts.packet_delimiter_byte)[:-1])
        check_nonce(packet_without_signature, nonce)
    # eliminate signature from packet
    return consts.packet_delimiter_byte.join(packet.split(consts.packet_delimiter_byte)[:-1])

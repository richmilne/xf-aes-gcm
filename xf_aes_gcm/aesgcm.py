# encoding: utf8
import os
import sys
import warnings

major, minor = [int(n) for n in sys.version.split('.')[:2]]
if major >= 3 and minor >= 6:
    with warnings.catch_warnings(record=True) as w:
        # Import something, anything, from the module so as to catch the
        # DeprecationWarning - and then subsequent imports won't trigger others.
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from cryptography import CryptographyDeprecationWarning
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

# Encrypt/decrypt functions based on examples provided at
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

def create_cipher_obj(key, iv, min_tag_length=None, encrypt=True):
    # Construct an AES-GCM Cipher object with the given key and IV.
    # An encryptor will be returned, unless `encrypt` in which case a decryptor
    # will be returned.
    mode = modes.GCM(iv)
    if min_tag_length is not None:
        mode = modes.GCM(iv, min_tag_length=max(4, min_tag_length))
    obj = Cipher(algorithms.AES(key), mode)
    return obj.encryptor() if encrypt is True else obj.decryptor()


def encrypt(key, iv, plaintext, associated_data=None):
    # Returns ciphertext and tag
    # tag always 16 bytes - test/verify

    encryptor = create_cipher_obj(key, iv)
    if associated_data:
        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (ciphertext, encryptor.tag)


def decrypt(key, iv, ciphertext, associated_data, tag, min_tag_length=None):

    # Document that, if no tag given, no verification is done.

    decryptor = create_cipher_obj(key, iv, min_tag_length, encrypt=False)
    if associated_data:
        # We put associated_data back in or the tag will fail to verify when we
        # finalize the decryptor.
        decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    plaintext = decryptor.update(ciphertext)
    if tag:
        # If the tag does not match an InvalidTag exception will be raised.
        decryptor.finalize_with_tag(tag)
    return plaintext
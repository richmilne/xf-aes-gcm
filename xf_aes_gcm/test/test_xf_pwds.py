import os
import unittest
import pytest

from xf_aes_gcm.aesgcm import encrypt
from xf_aes_gcm import (
    GCM_TAG_LENGTH_12, KEY_BYTES, IV,
    xf_pwd_encrypt, xf_pwd_decrypt
)

class TestDefaultData(unittest.TestCase):
    plaintext = 'Sw0rdf/sh1!'
    # This ciphertext was produced by the Xpressfeed installer. This test suite
    # is to verify that we can reproduce and decode it.
    ciphertext = '9e82e08e1c25eb3655f9d31cff1ec19bd28fc3aeb0ddbf'

    def test_decrypt(self):
        recover = xf_pwd_decrypt(self.ciphertext)
        pwd = recover.decode('utf8')
        self.assertEqual(pwd, self.plaintext)

    def test_encrypt(self):
        ciphertext = xf_pwd_encrypt(self.plaintext)
        self.assertEqual(ciphertext, self.ciphertext)

        # As Xfeed tags are shorter, verify that XFeed ciphertexts are a subset
        # of the full ones produced by the crypto functions.
        cipher, tag = encrypt(KEY_BYTES, IV, self.plaintext.encode('utf8'))
        check = (cipher + tag).hex()
        self.assertTrue(len(check) > len(ciphertext))
        self.assertTrue(check[:len(ciphertext)] == ciphertext)


if __name__ == '__main__':
    unittest.main()

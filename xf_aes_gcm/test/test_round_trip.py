import os
import unittest
import pytest
from functools import partial

from xf_aes_gcm import aesgcm
from cryptography.exceptions import InvalidTag

class TestDefaultData(unittest.TestCase):
    test_unicode = "61D096E4B8ADF0908D86"   # Encodes the chars aÐ–ä¸­í €í½†
    plaintext = bytes.fromhex(test_unicode) # print(plaintext.decode('utf8'))
    aad = b'authenticated but not encrypted payload'

    def setUp(self):
        self.iv = os.urandom(12)
        self.key = os.urandom(16)
        self.encrypt = partial(aesgcm.encrypt, self.key, self.iv,
                               self.plaintext)
        self.decrypt = partial(aesgcm.decrypt, self.key, self.iv)


class TestTagLengths(TestDefaultData):
    def test_invariant_tag_length(self):
        # Verify that, no matter what min_tag_length we pass in to the encrypt
        # (and hence the GCM mode object) the return tag is always 16 bytes
        # long.
        # In other words, if you want your tags a certain length, you have to
        # truncate them yourself
        last_cipher = None
        last_tag = None
        for tag_len in [None, 2, 4, 12, 16, 18]:
            encryptor = aesgcm.create_cipher_obj(self.key, self.iv,
                                                 min_tag_length=tag_len)
            ciphertext = encryptor.update(self.plaintext) + encryptor.finalize()
            tag = encryptor.tag
            if last_cipher is None: last_cipher = ciphertext
            if last_tag is None: last_tag = tag

            self.assertEqual(last_cipher, ciphertext)
            self.assertEqual(last_tag, tag)
            self.assertEqual(len(tag), 16)

    def test_decrypt_diff_tag_lengths(self):
        cipher, tag = self.encrypt(self.aad)

        assert len(tag) > 10
        tag = tag[:10]
        decrypt = partial(self.decrypt, cipher, self.aad, tag)

        # Decrypt will still validate if you pass in tag lengths less than or
        # equal to the length of the tag passed in - even if it's not the full,
        # original tag
        for tag_len in [8, 10]:
            recover = decrypt(min_tag_length=tag_len)
            self.assertEqual(recover, self.plaintext)
        # But you can't pass a tag length longer than the tag used:
        with self.assertRaises(ValueError) as context:
            recover = decrypt(min_tag_length=12)


class TestRoundTrip(TestDefaultData):
# AAD passed in on encryption:
#   On decrypt:
#       AAD   |   Tag
#     --------+--------
#     correct | correct    [ 1]
#      wrong  | correct    [ 2]
#     missing | correct    [ 3]
#     correct |  wrong     [ 4]
#      wrong  |  wrong     [ 5]
#     missing |  wrong     [ 6]
#     correct | missing    [ 7]
#      wrong  | missing    [ 8]
#     missing | missing    [ 9]

    def test_round_trip(self):
        # Verify that we can decrypt ciphertexts encrypted by this module and
        # recover our original text.
        aads = [None, b'', self.aad]
        tag_lens = [None, 12]
        last_cipher = None
        for tag_len in tag_lens:
            for aad in aads:
                cipher, tag = self.encrypt(aad)
                if last_cipher is None: last_cipher = cipher
                # Verify neither tag length nor aad have any effect on ciphertxt
                self.assertEqual(last_cipher, cipher)
                recover = self.decrypt(cipher, aad, tag, tag_len)
                self.assertEqual(recover, self.plaintext)

    def test_aad_validated_when_tag_present(self):
        cipher, tag = self.encrypt(self.aad)
        decrypt = partial(self.decrypt, cipher)

        recover = decrypt(self.aad, tag)
        self.assertEqual(recover, self.plaintext)

        wrong_tag = tag[:-1]+b'0'
        wrong_aad = b'wrong'
        # If a tag is present upon decryption
        #  - the tag must be correct,
        #  - associated data must be present,
        #  - associated data must match the original data passed in.
        with self.assertRaises(InvalidTag) as context:
            decrypt(wrong_aad, tag)                              # case [ 2]
        with self.assertRaises(InvalidTag) as context:
            decrypt(self.aad, wrong_tag)                         # case [ 4]
        with self.assertRaises(InvalidTag) as context:
            decrypt(wrong_aad, wrong_tag)                        # case [ 5]
        with self.assertRaises(InvalidTag) as context:
            decrypt(None, wrong_tag)                             # case [ 6]
        # However, if no tag is present, aad is not validated.
        recover = decrypt(wrong_aad, None)                       # case [ 8]
        self.assertEqual(recover, self.plaintext)

    def test_tag_missing_on_decrypt_aad_present(self):
        # If aad was passed in on encryption, it must be present on decryption,
        # no matter what the value of the tag
        cipher, tag = self.encrypt(self.aad)
        decrypt = partial(self.decrypt, cipher)

        for tag_ in [None, tag]:
            recovered = decrypt(self.aad, tag_)              # cases [ 7], [ 1]
            self.assertEqual(recovered, self.plaintext)
        # Previous tests verified that aad had to be the same. Here we verify
        # that it must be present - it can't be None, no matter the tag value.
        for tag_ in [None, tag]:
            with self.assertRaises(InvalidTag) as context:
                decrypt(None, tag)                           # cases [ 9], [ 3]

    def test_tag_missing_on_decrypt_aad_missing(self):
        # If aad was not passed in on encryption, it's not required on decrypt -
        # no matter the tag value.
        cipher, tag = self.encrypt()
        for tag_ in [None, tag]:
            recovered = self.decrypt(cipher, None, tag_)
            self.assertEqual(recovered, self.plaintext)


if __name__ == '__main__':
    unittest.main()

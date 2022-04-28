#! /usr/bin/env python
"""En-/Decrypt (and optionally authenticate) data using AES-GCM.

Input files are read as binary data, and output is written (again as binary)
to stdout - which means you either need to write it directly to a file, or
process it further along the pipeline.

Some examples to make this clear:

$ echo -n 'Sw0rdf/sh1!' > plaintext
$ xf-aes-gcm -f plaintext > ciphertext
$ xxd -ps ciphertext
9e82e08e1c25eb3655f9d31cff1ec19bd28fc3aeb0ddbf

You don't need to read the plaintext directly from a file; you can read it
from stdin:

$ echo -n 'Sw0rdf/sh1!' | xf-aes-gcm | xxd -ps
9e82e08e1c25eb3655f9d31cff1ec19bd28fc3aeb0ddbf

Encryption is the default option. You need to be explicit if you'd like to
decrypt:

$ xf-aes-gcm -f ciphertext DEC
Sw0rdf/sh1!

While encrypting some data, you may simultaneously pass in additional data
whose authenticity you'd like to verify at a later stage. This data must
have been previously saved to a file:

$ echo -n 'authenticated but not encrypted payload' > aad
$ echo -n 'Sw0rdf/sh1!' | xf-aes-gcm --aad aad > ciphertext
$ xxd -ps ciphertext
9e82e08e1c25eb3655f9d328e85c0279a0f1ed59572978

(Notice how, when compared to the earlier example, the bytes corresponding
to the encrypted plaintext are the same, but those for the tag are
different.)

When decrypting ciphertexts that were constructed with additional data, you
need to pass in precisely the same additional data:

$ cat ciphertext | xf-aes-gcm --aad aad DEC
Sw0rdf/sh1!

If you don't pass in precisely the same data, you'll see an error message:

$ echo -n '.' >> aad
$ cat ciphertext | xf-aes-gcm --aad aad DEC
Could not verify...

If you'd like to dispense with verification yet still try recover the
original plaintext, try the --no-verify flag:

$ cat ciphertext | xf-aes-gcm --aad aad DEC --no-verify
Sw0rdf/sh1!

Be aware that, for compatibility with the Xpressfeed algorithms, a tag
length of 12 bytes, less than the maximum tag length available, is used by
default. Use the --tag option to specify the full (or different) lengths:

$ echo -n 'Sw0rdf/sh1!' | xf-aes-gcm --tag-len 16 | xxd -ps
9e82e08e1c25eb3655f9d31cff1ec19bd28fc3aeb0ddbf12e1df19

When decrypting, you must use a tag length equal to the length used when the
data was encrypted, otherwise you'll see the same error encountered earlier:

$ echo -n 'Sw0rdf/sh1!' | xf-aes-gcm --tag-len 14 > ciphertext
$ xf-aes-gcm --tag-len 12 -f ciphertext DEC
Could not verify...

Disabling verification will suppress the error and return as much of the
plaintext as can be recovered - which may be more or less than the original:

$ xf-aes-gcm --tag-len 12 -f ciphertext DEC --no-verify | xxd
00000000: 5377 3072 6466 2f73 6831 2178 fe         Sw0rdf/sh1!x.
$ xf-aes-gcm --tag-len 16 -f ciphertext DEC --no-verify | xxd
00000000: 5377 3072 6466 2f73 68                   Sw0rdf/sh

Lastly, here's a simple shell function to help you generate keys and nonces
of the required byte lengths, defaulting to 12 bytes:

$ function rand-hex {
>    num_bytes="${1:-12}"
>    head -c $num_bytes /dev/urandom | xxd -ps -c $num_bytes
> }

You could use it like this:

$ IV=$(rand-hex)
$ KEY=$(rand-hex 16) # or 24 or 32
$ echo -n 'Sw0rdf/sh1!' | xf-aes-gcm --key $KEY --iv $IV | xxd -ps
cc59216b77bf832f2705de5cc26a9d4a51f03893345077
$ echo -n cc59216b77bf832f2705de5cc26a9d | xxd -r -p |
>     xf-aes-gcm -k $KEY -i $IV -t 4 DEC
Sw0rdf/sh1!
"""
import argparse
import os
import sys
import pathlib

from . import aesgcm

# The directory containing this file
_HERE = pathlib.Path(__file__).parent

# The text of the VERSION file
_VERSION = (_HERE / 'VERSION').read_text()

# Values taken directly from the Xpressfeed jar (buildnumber=45,
# loaderversion=5.10.3), in com/capitaliq/common/ObjectLibrary.class
# (See also com/capitaliq/loader/control/PrivacyUtil.class for older key ;) )
CIPHER_ALGORITHM_AES_NOPADDING = "AES/GCM/NoPadding"
GCM_TAG_LENGTH_12 = 12
KEY_BYTES = [45, 61, 36, -33, -124, -82, 53, -112, -84, -37, 113, 99, -37, -31, -97, -71]
IV = [56, 95, 82, 112, 9, -93, 123, 11, 84, -80, -87, 127]

# In Java, negative numbers are stored, in N bits, by decrementing from zero.
# Thus -1 is always 2^(N-1). The lowest negative number that can be represented
# is -2^(N-1), the highest (2^(N-1))-1.
# So to convert a negative number to an unsigned bytes, add 2^N.
_complement = lambda int_list: [(2**8)+b if b<0 else b for b in int_list]

KEY_BYTES = bytes(_complement(KEY_BYTES))
IV = bytes(_complement(IV))

def validate_bit_length(bytes_, valid_bit_lengths):
    """Verify the bit length of the `bytes_` object.

    `valid_bit_lengths` is a non-empty list of allowed integer bit lengths.
    ArgumentTypeError is raised if the bit length isn't in the list."""
    assert valid_bit_lengths
    num_bits = len(bytes_)*8
    if num_bits not in valid_bit_lengths:
        msg = 'Invalid key bit size (%s); '
        msg += 'should be one of the following sizes: %s.'
        msg = msg % (num_bits, valid_bit_lengths)
        raise argparse.ArgumentTypeError(msg)


def validate_decode_key(hex_input, valid_bit_lengths=[128, 192, 256]):
    """Converts a hex-encoded string to bytes and checks its length."""
    key = bytes.fromhex(hex_input)
    validate_bit_length(key, valid_bit_lengths)
    return key


def validate_range_type(lower=0, upper=16):
    # Return a function which will check int inputs lie within the (incl.) range
    def validate_range(input):
        value = int(input)
        if lower <= value <= upper:
            return value
        else:
            msg = 'value not in range %d-%d' % (lower, upper)
            raise argparse.ArgumentTypeError(msg)
    return validate_range


def read_stream_or_file(handle):
    # handle will be closed when no more data is available.
    # print('infile', type(handle), handle)
    buffer = bytearray()
    chunk = handle.read()
    while chunk:
        # print('Byte chunk:', chunk)
        buffer.extend(chunk)
        chunk = handle.read()
    handle.close()
    return buffer


def _read_args():
    """Retrieve and validate command-line arguments."""

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)

    parser.add_argument("-v", "--version",
                        help="Show version number and exit.",
                        action="version",
                        version=_VERSION)

    parser.add_argument("-k", "--key",
        default=KEY_BYTES.hex(),
        type=validate_decode_key,
        help=("Encryption key of 128, 192 or 256 bits (16, 24 or 32 bytes), "
              "hex-encoded. Default is the Xpressfeed key, '%(default)s'.")
    )

    parser.add_argument("-i", "--iv",
        default=IV.hex(),
        type=bytes.fromhex,
        help=("Initialisation Vector (IV), or nonce, hex-encoded. "
              "Recommended length 96 bits (12 bytes). "
              "Default is the Xpressfeed IV, '%(default)s'.")
    )

    parser.add_argument("-t", "--tag-len",
        default=GCM_TAG_LENGTH_12,
        type=validate_range_type(4,16),
        help=("Length, in bytes, of the tag appended to the end of the "
              "ciphertext. Default is the Xpressfeed length of %(default)s.")
    )

    parser.add_argument("op",
        choices=['ENC', 'DEC'],
        default='ENC',
        nargs='?',
        help=("The operation to be performed - ENCryption or DECryption. "
              "Default: %(default)s.")
    )

    parser.add_argument("-f",
        nargs='?',
        type=argparse.FileType(mode='rb'),
        # To read binary data from stdin you need to use its 'buffer' attribute.
        default=sys.stdin.buffer,
        help="File to be en-/decrypted. Defaults to stdin if not present."
    )

    parser.add_argument("-a", "--aad",
        type=argparse.FileType(mode='rb'),
        help="File containing associated plaintext data to be authenticated."
    )

    parser.add_argument("--no-verify",
        action='store_true',
        help=("Signal that you do not want to verify the cipher tag "
              "upon decryption.")
    )

    args = parser.parse_args()
    return args


def xf_pwd_encrypt(pwd):
    # pwd is python string (i.e. UTF8 decoded)
    # Tests have verified that the crypto functions always return 16-bit tags,
    # so we have to truncate them ourselves.
    cipher, tag = aesgcm.encrypt(KEY_BYTES, IV, pwd.encode('utf8'))
    tag = tag[:GCM_TAG_LENGTH_12]
    return (cipher + tag).hex()


def xf_pwd_decrypt(ciphertxt):
    # pwd is string of hex digits
    pad = ' '*len(ciphertxt)

    tag_length = GCM_TAG_LENGTH_12 * 2
    aad = b''
    # Xpressfeed appends tag after encrypted password
    tag    = ciphertxt[-tag_length:]
    cipher = ciphertxt[:-tag_length]
    if 0:
        print(cipher)
        print(pad[:-tag_length], end='')
        print(tag)
    tag, cipher = map(bytes.fromhex, [tag, cipher])

    recovered = aesgcm.decrypt(KEY_BYTES, IV, cipher, b'', tag,
                               GCM_TAG_LENGTH_12)
    return recovered


def encrypt(key, iv, tag_len, input, aad=None):
    cipher, tag = aesgcm.encrypt(key, iv, input, aad)
    assert len(tag) >= tag_len
    if tag_len < len(tag):
        tag = tag[:tag_len]
    ciphertext = cipher+tag
    # print(ciphertext, type(ciphertext))
    sys.stdout.buffer.write(ciphertext)
    #print(cipher + tag, file=sys.stdout.buffer)


def decrypt(key, iv, tag_len, input, aad=None, verify=True):
    # Higher level function, which attempts to return plaintext even if tag is
    # wrong or data fails to validate.
    # tag is appended to end of ciphertext
    cipher = bytes(input[:-tag_len])
    tag = bytes(input[-tag_len:])
    # print('Cipher', cipher.hex())
    # print('Tag', tag.hex())
    tag = tag if verify else None
    try:
        recover = aesgcm.decrypt(key, iv, cipher, aad, tag, tag_len)
        sys.stdout.buffer.write(recover)
    except aesgcm.InvalidTag:
        msg = ('Could not verify either, or both, of the authentication tag '
              'and the associated data.')
        print(msg, file=sys.stderr)


def xf_aes_gcm():

    args = _read_args()
    if 0: print(args)
    key, iv, tag_len = args.key, args.iv, args.tag_len
    input = read_stream_or_file(args.f)
    if not input:
        print('Input file/stream empty!', file=sys.stderr)
    aad = read_stream_or_file(args.aad) if args.aad else None

    if args.op == 'ENC':
        encrypt(key, iv, tag_len, input, aad)
    else:
        decrypt(key, iv, tag_len, input, aad, not args.no_verify)

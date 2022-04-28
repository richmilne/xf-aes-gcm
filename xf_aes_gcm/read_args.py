#! /usr/bin/env python
import argparse
import os
import sys
import pathlib

from . import aesgcm

# The directory containing this file
_HERE = pathlib.Path(__file__).parent

# The text of the VERSION file
_VERSION = (_HERE / 'VERSION').read_text()

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
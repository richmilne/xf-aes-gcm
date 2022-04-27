#! /usr/bin/env python
"""En-/Decrypt (and optionally validate) data with the AES-GCM algorithm."""
import argparse
import os
import sys
import pathlib

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the VERSION file
__VERSION__ = (HERE / 'VERSION').read_text()


def _read_args():
    """Retrieve and validate command-line arguments."""

    parser = argparse.ArgumentParser(
        # formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)

    parser.add_argument("-v", "--version",
                        help="Show version number and exit.",
                        action="version",
                        version=__VERSION__)

    args = parser.parse_args()
    return args


def xf_aes_gcm():
    args = _read_args()
    print(args)
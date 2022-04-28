
# AES-GCM en-/decryption, with AEAD and support for Xpressfeed passwords

This package's aim is to be able to handle general AES-GCM encryption and decryption, while still providing the constants and functionality required to inter-operate with S&P Global's Xpressfeed applications, as they use the same algorithm.

In essence, this package should be capable of producing and reading the same ciphertexts as the Xpressfeed applications, and with the minimum of configuration at that. As an example, here we decrypt a password produced by the Xpressfeed installer:

````
$ echo -n 9e82e08e1c25eb3655f9d31cff1ec19bd28fc3aeb0ddbf | xxd -r -p | xf-aes-gcm DEC
Sw0rdf/sh1!
````

## Installing

First, ensure you are installing into a virtual environment:

    python3 -m venv venv
    source ./venv/bin/activate
    pip install --upgrade pip

Then use `pip` to install this package and its dependencies:

    pip install -v \
    --upgrade --force-reinstall \
    xf-aes-gcm

There may be more recent, or beta, packages in the Test PyPI repository. To obtain one of these packages add the option

    --extra-index-url https://test.pypi.org/simple/

to the above command.

## Command-line options/usage

**`xf-aes-gcm`**

    [-h|--help] [-v|--version]
    [-k KEY] [-i IV] [-t TAG_LEN] [-f [F]] [-a AAD]
    [--no-verify] [{ENC,DEC}]

Use **`xf-aes-gcm`**` -h` to bring up more details on these options and their default values, as well as several examples of how to use this package.
"""Setup for the xf-aes-gcm module and command-line script."""
import os
import pathlib
import datetime
import json

from setuptools import setup, find_packages

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / 'README.md').read_text()

BASE_VERSION = '1.0.1'
PKG_NAME = 'xf_aes_gcm'
DESC = ('A general AES-GCM en-/decryption utility with support for additional '
        'data (AEAD) and tweaks to work with the passwords encrypted by '
        "S&P Global's Xpressfeed applications, which use this algorithm.")
GIT_URL='https://github.com/richmilne/xf-aes-gcm/releases/tag/v1.0.0'
# Replace the default URL given above by one defined in the environment
# (and one should be defined if this package is built by Jenkins)
GIT_URL = os.getenv('GIT_URL', GIT_URL)

_PKG_NAME=PKG_NAME.replace('_', '-').replace(' ', '-').lower()

def create_version_struct():
    now = datetime.datetime.now()
    version = [BASE_VERSION]# + [str(s) for s in now.timetuple()[:5]]
    version = '.'.join(version)
    ver = {
        'build': {
            'name': _PKG_NAME,
            'time': now.isoformat(),
            'version': version,
            # 'description': DESC,
            # We no longer include DESC because python's argparse formats (i.e.
            # linebreaks) long descriptions, which breaks the JSON structure and
            # makes it invalid. You can't use python formatters on some
            # args, and not others. If you want to preserve version structure -
            # all your args will have to be unformatted.
        },
        'git': {
            'url': GIT_URL
        }
    }
    # When run as part of Jenkins build, the JENKINS_URL env var - and all the
    # others referenced in this block - should be available
    jenkins = os.getenv('JENKINS_URL')
    if jenkins:
        ver['build']['build-url'] = os.getenv('BUILD_URL')
        ver['git'].update({
            'branch': os.getenv('GIT_BRANCH'),
            'commit': {
                'id': os.getenv('GIT_COMMIT'),
                # 'time': '   '
            }
        })
    return version, ver

__VERSION__, ver_struct = create_version_struct()
with open(HERE / PKG_NAME / 'VERSION', 'w') as handle:
    handle.write(json.dumps(ver_struct, indent=2))

setup(
    # If you change name, also need to change it in package init, as it is
    # used to retrieve version
    name=_PKG_NAME,
    version=__VERSION__,
    url=GIT_URL,
    description=DESC,
    long_description=README,
    # Needed by PyPI, which expects reStructuredText by default.
    long_description_content_type='text/markdown',
    author='Richard Milne',
    author_email='richmilne@hotmail.com',
    license='GPLv3',
    packages=find_packages(),
    include_package_data=True,   # Included files given in MANIFEST.in
    entry_points={
        'console_scripts': [
            '%(_PKG_NAME)s=%(PKG_NAME)s:%(PKG_NAME)s' % locals()
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
    ],
    install_requires = [
        'cryptography',
    ],
)
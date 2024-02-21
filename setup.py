import os.path
import re
import setuptools


def find_version(filename):
    with open(filename) as f:
        text = f.read()
    match = re.search(r"^_version_str = '(.*)'$", text, re.MULTILINE)
    if not match:
        raise RuntimeError('cannot find version')
    return match.group(1)


tld = os.path.abspath(os.path.dirname(__file__))
version = find_version(os.path.join(tld, 'bitcoinx', '__init__.py'))


setuptools.setup(
    version=version,
    packages=['bitcoinx'],
    # Tell setuptools to include data files specified by MANIFEST.in.
    include_package_data=True,
    download_url=('https://github.com/kyuupichan/bitcoinX/archive/'
                  f'{version}.tar.gz'),
    long_description=(
        'Library of Bitcoin functions covering network protocol, consensus, '
        'transactions, scripting and signing.'
    ),
)

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
    name='bitcoinX',
    version=version,
    python_requires='>=3.6',
    install_requires=['attrs', 'pyaes', 'electrumsv-secp256k1'],
    packages=['bitcoinx'],
    description='Library of Bitcoin functions',
    author='Neil Booth',
    author_email='kyuupichan@gmail.com',
    license='MIT Licence',
    url='https://github.com/kyuupichan/bitcoinX',
    download_url=('https://github.com/kyuupichan/bitcoinX/archive/'
                  f'{version}.tar.gz'),
    long_description=(
        'Library of Bitcoin functions covering network protocol, consensus, '
        'transactions, scripting and signing.'
    ),
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        "Programming Language :: Python :: 3.6",
        'Topic :: Internet',
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)

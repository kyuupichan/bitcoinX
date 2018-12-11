import setuptools

from bitcoinx import _version_str as version


setuptools.setup(
    name='bitcoinX',
    version=version,
    python_requires='>=3.6',
    install_requires=['attrs'],
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

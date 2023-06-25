.. image:: https://badge.fury.io/py/bitcoinX.svg
    :target: http://badge.fury.io/py/bitcoinX
.. image:: https://travis-ci.org/kyuupichan/bitcoinX.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/bitcoinX
.. image:: https://coveralls.io/repos/github/kyuupichan/bitcoinX/badge.svg
    :target: https://coveralls.io/github/kyuupichan/bitcoinX

========
bitcoinX
========

A Python Bitcoin library that will grow to encompass network protocol,
consensus, transactions, scripting and signing.

  :Licence: OpenBSV
  :Language: Python (>= 3.8)
  :Author: Neil Booth


Documentation
=============

In time.


ChangeLog
=========

0.8.0
-----

Replace old Headers implementation

0.7.1
-----

- fix a typo that resulted in inefficient block header searching in rare cases

0.7.0
-----

- as OpenSSL has removed ripemd160, take it from pycryptodomex, now a required package.  Remove
  dependency on pyaes as a result as pycryptodomex can do AES too.

0.6.0
-----

- remove deprecated symbols and remaining references to coin; they are now networks


0.5.0
-----

- add merkle_root() and grind_header()
- add pickling support for the Headers object (rt121212121)

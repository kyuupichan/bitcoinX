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

  :Licence: MIT
  :Language: Python (>= 3.7)
  :Author: Neil Booth


Documentation
=============

In time.


ChangeLog
=========

0.4.0
-----

- Switch to Open BSV License version 3
- Add a script interpreter.  This is extensively tested and I believe it is compatible with
  bitcoind if passed the appropriate arguments.  The API is very likely to change, particularly
  when I introduce a script debugger.
- Script: new APIs and minor changes needed for the script interpreter
- Cleanup / rewrite of the Signature class for the script interpreter.  The API is
  quite different.
- Tx: supports old-style signature hashing for before the BCH fork
- TxOut: add null() API
- ElectrumMnemonic:
  - new_to_seed() converts a new-style mnemonic and passphrase to a seed
  - normalize_new() normalizes a new-style mnemonic
  - add an Electrum-compatible passphrase mangler

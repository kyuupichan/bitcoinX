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


0.4.2/0.4.3
-----------

- Coin renamed to Network; all_coins to all_networks.  Those two symbols are deprecated and
  will be removed in 0.5.
- Network constructor requires names be used
- network.name renamed network.full_name; network.name is now a short name
- networks have new attribtes: BIP65_height, BIP66_height, CSV_height, UAHF_height, DAA_height,
  genesis_height and magic.
- new symbol networks_by_name
- get attrs to play nicely with type checking.  Fix regtest data. (Roger Taylor)


0.4.1
-----

- Script.to_asm(): for truncated scripts it now returns all words up to the truncation point,
  for which it returns '[script error]' by default, but alternative text can be supplied.
- new API pack_signed_message() related to message signing; this function was previously
  internal.

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

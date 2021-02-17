# Copyright (c) 2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#


__all__ = (
    'JSONFlags', 'CURVE_ORDER', 'HALF_CURVE_ORDER', 'SIGNED_MESSAGE_PREFIX',
)


from enum import IntFlag

from .packing import pack_varbytes


CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
HALF_CURVE_ORDER = CURVE_ORDER // 2
SIGNED_MESSAGE_PREFIX = pack_varbytes('Bitcoin Signed Message:\n'.encode())


class JSONFlags(IntFlag):
    '''Flags controlling conversion of transactions and scripts to JSON.'''
    # Include the index of each input
    ENUMERATE_INPUTS = 1 << 0
    # Include the index of each output
    ENUMERATE_OUTPUTS = 1 << 1
    # Include the transaction size in bytes
    SIZE = 1 << 2
    # Include a human-readable description of the locktime constraint is output
    LOCKTIME_MEANING = 1 << 3
    # Include classification of output scripts
    CLASSIFY_OUTPUT_SCRIPT = 1 << 4
    # Display signature sighashes as text
    SIGHASH_MEANING = 1 << 5

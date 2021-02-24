# Copyright (c) 2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Exception hierarchy.'''

__all__ = (
    'Base58Error', 'DecryptionError',
    'ChainException', 'MissingHeader', 'IncorrectBits', 'InsufficientPoW',
    'ScriptError', 'TruncatedScriptError', 'InterpreterError',
    'StackSizeTooLarge', 'TooManyOps', 'MinimalEncodingError', 'CleanStackError',
    'ScriptTooLarge', 'MinimalIfError', 'DivisionByZero', 'NegativeShiftCount',
    'InvalidPushSize', 'DisabledOpcode', 'UnbalancedConditional', 'InvalidStackOperation',
    'VerifyFailed', 'OpReturnError', 'InvalidOpcode', 'InvalidSplit', 'ImpossibleEncoding',
    'InvalidNumber', 'InvalidOperandSize', 'EqualVerifyFailed', 'NullFailError',
    'InvalidPublicKeyEncoding', 'InvalidPublicKeyCount', 'InvalidSignature', 'NullDummyError',
    'CheckSigVerifyFailed', 'CheckMultiSigVerifyFailed', 'UpgradeableNopError',
    'NumEqualVerifyFailed', 'InvalidSignatureCount', 'PushOnlyError', 'LockTimeError',
    'StackMemoryUsageError',
)


#
# Exception Hierarchy
#


class Base58Error(ValueError):
    '''Exception used for Base58 errors.'''


class ChainException(Exception):
    '''Base class of exceptions raised in chain.py.'''


class MissingHeader(ChainException):
    '''Raised by Headers.connect() when the previous header is missing.'''


class IncorrectBits(ChainException):
    '''Raised when a header has bits other than those required by the protocol.'''

    def __init__(self, header, required_bits):
        super().__init__(header, required_bits)
        self.header = header
        self.required_bits = required_bits

    def __str__(self):
        return f'header {self.header} requires bits 0x{self.required_bits}'


class InsufficientPoW(ChainException):
    '''Raised when a header has less PoW than required by the protocol.'''

    def __init__(self, header):
        super().__init__(header)
        self.header = header

    def __str__(self):
        return (f'header f{self.header} hash value f{self.header.hash_value()} exceeds '
                f'its target {self.header.target()}')


class DecryptionError(ValueError):
    '''Raised by PrivateKey.decrypt_message for various failures.'''


class ScriptError(Exception):
    '''Base class for script errors.'''


class TruncatedScriptError(ScriptError):
    '''Raised when a script is truncated because a pushed item is not all present.'''


class InterpreterError(ScriptError):
    '''Base class for interpreter errors.'''


class ScriptTooLarge(InterpreterError):
    '''Raised when a script is too long.'''


class TooManyOps(InterpreterError):
    '''Raised when a script contains too many operations.'''


class InvalidStackOperation(InterpreterError):
    '''Raised when an opcode wants to access items deyond the stack depth.'''


class MinimalEncodingError(InterpreterError):
    '''Raised when a stack push happens not using the minimally-encoded push operation, or
    of a non-minally-encoded number.'''


class InvalidPushSize(InterpreterError):
    '''Raised when an item size is negative or too large.'''


class ImpossibleEncoding(InterpreterError):
    '''Raised when an OP_NUM2BIN encoding will not fit in the required size.'''


class InvalidNumber(InterpreterError):
    '''Raised when an OP_BIN2NUM result exceeds the maximum number size.'''


class InvalidOperandSize(InterpreterError):
    '''Raised when the operands to a binary operator are of invalid sizes.'''


class StackSizeTooLarge(InterpreterError):
    '''Raised when the stack size it too large.'''


class DivisionByZero(InterpreterError):
    '''Raised when a division or modulo by zero is executed.'''


class MinimalIfError(InterpreterError):
    '''Raised when the top of stack is not boolean processing OP_IF or OP_NOTIF.'''


class DisabledOpcode(InterpreterError):
    '''Raised when a disabled opcode is encountered.'''


class InvalidOpcode(InterpreterError):
    '''Raised when an invalid opcode is encountered.'''


class NegativeShiftCount(InterpreterError):
    '''Raised when a shift of a negative number of bits is encountered.'''


class InvalidSplit(InterpreterError):
    '''Raised when trying to split an item at an invalid position.'''


class UnbalancedConditional(InterpreterError):
    '''Raised when a script contains unepxected OP_ELSE, OP_ENDIF conditionals, or if
    open condition blocks are unterminated.'''


class OpReturnError(InterpreterError):
    '''OP_RETURN was encountered pre-genesis.'''


class InvalidPublicKeyEncoding(InterpreterError):
    '''Raised on an invalid public key encoding when checking a signature.'''


class InvalidSignature(InterpreterError):
    '''Raised on various invalid signature encodings when checking a signature.'''


class NullFailError(InterpreterError):
    '''Raised if a signature check failed on a non-null signature with REQUIRE_NULLFAIL.'''


class NullDummyError(InterpreterError):
    '''Raised if the dummy multisig argument is non-null with REQUIRE_NULLDUMMY.'''


class UpgradeableNopError(InterpreterError):
    '''Raised if an upgradeable NOP is encountered.'''


class InvalidPublicKeyCount(InterpreterError):
    '''Raised if the number of public keys in an OP_CHECKMULTISIG operation is out of range.'''


class InvalidSignatureCount(InterpreterError):
    '''Raised if the number of sigs in an OP_CHECKMULTISIG operation is out of range.'''


class PushOnlyError(InterpreterError):
    '''Raised if a script-sig is not pushdata only with REQUIRE_PUSH_ONLY.'''


class CleanStackError(InterpreterError):
    '''Raised if the stack is not clean after verify_script() with REQUIRE_CLEANSTACK.'''


class LockTimeError(InterpreterError):
    '''Raised for various failures of OP_CHECKLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY.'''


class StackMemoryUsageError(InterpreterError):
    '''Raised when stack memory usage gets too large.'''


class VerifyFailed(InterpreterError):
    '''OP_VERIFY was executed and the top of stack was zero.'''


class EqualVerifyFailed(VerifyFailed):
    '''OP_EQUALVERIFY was executed and it failed.'''


class NumEqualVerifyFailed(VerifyFailed):
    '''OP_NUMEQUALVERIFY was executed and it failed.'''


class CheckSigVerifyFailed(VerifyFailed):
    '''OP_CHECKSIGVERIFY was executed and it failed.'''


class CheckMultiSigVerifyFailed(VerifyFailed):
    '''OP_CHECKMULTISIGVERIFY was executed and it failed.'''

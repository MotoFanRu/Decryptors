#!/usr/bin/env python3
'''
Decrypt VictorGSM.net Motorola .vfl flash files.

The VFL crypt routine is the DCPcrypt Blowfish implementation found in the
VictorGSM executable.  The important details are:

- key = SHA1 of the binary data represented by the embedded hex string
- the DCPcrypt compatibility IV path starts with 8 FF bytes and encrypts that block
- the file is processed as one continuous Blowfish-CBC stream
- the first 100 bytes are special because 100 = 12 * 8 + 4
- the final 4-byte part of the header is processed with Encrypt(CV) as a
  keystream and DOES NOT advance the CBC feedback value
- therefore the payload starts with CV = encrypted file bytes 0x58..0x5F

Usage:
    vfl_decrypt.py <file.vfl> [out.bin]
'''

import hashlib
import sys
import warnings
from pathlib import Path

warnings.filterwarnings('ignore')

from cryptography.hazmat.primitives.ciphers import Cipher, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish

PASSPHRASE = (
    b'0C77F10A2AD7F73ECA795DFAD608E35C40B53D52A8D8AA12509607ED08F3B6C'
    b'002DF86ABE123C48DF81EF0B6C243C10DF5D7BCC90E27B71DEC9'
)

HEADER_SIZE = 0x64
FULL_HEADER_SIZE = 0x60
BLOCK_SIZE = 8


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _ecb_block(key, encrypt, block):
    cipher = Cipher(Blowfish(key), modes.ECB())
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(block) + op.finalize()


def _decrypt_full_blocks(data, key, feedback):
    '''Decrypt complete 8-byte CBC blocks and return (plaintext, feedback).'''
    out = bytearray()
    full = len(data) // BLOCK_SIZE * BLOCK_SIZE

    for i in range(0, full, BLOCK_SIZE):
        ct = data[i:i + BLOCK_SIZE]
        pt = _xor(_ecb_block(key, False, ct), feedback)
        out += pt
        feedback = ct

    return bytes(out), feedback


def decrypt_vfl(data, passphrase=PASSPHRASE):
    if len(data) < HEADER_SIZE:
        raise ValueError('VFL file is shorter than the 100-byte header')

    key = hashlib.sha1(passphrase).digest()

    # DCPcrypt's IV initialization in sub_47F2C8:
    # FillChar(IV, 8, $FF), then encrypt IV in-place.
    feedback = _ecb_block(key, True, b'\xff' * BLOCK_SIZE)
    out = bytearray()

    # The original decrypt routine is called with exactly 100 bytes for the
    # header.  96 bytes are complete CBC blocks; the remaining 4 bytes use
    # Encrypt(feedback) as a keystream and do not update feedback.
    plain, feedback = _decrypt_full_blocks(
        data[:FULL_HEADER_SIZE], key, feedback
    )
    out += plain

    header_tail = data[FULL_HEADER_SIZE:HEADER_SIZE]
    keystream = _ecb_block(key, True, feedback)
    out += _xor(header_tail, keystream[:len(header_tail)])

    # Continue directly into CG data.  No reinitialization and no reset at
    # CG boundaries or at the 0x2000-byte file I/O buffer boundary.
    payload = data[HEADER_SIZE:]
    plain, feedback = _decrypt_full_blocks(payload, key, feedback)
    out += plain

    payload_tail_start = HEADER_SIZE + (len(payload) // BLOCK_SIZE * BLOCK_SIZE)
    payload_tail = data[payload_tail_start:]

    if payload_tail:
        keystream = _ecb_block(key, True, feedback)
        out += _xor(payload_tail, keystream[:len(payload_tail)])

    return bytes(out)


def main(argv):
    if not 2 <= len(argv) <= 3:
        sys.stderr.write(__doc__)
        return 2

    src = Path(argv[1])
    dst = Path(argv[2]) if len(argv) == 3 else src.with_suffix('.decoded.bin')

    try:
        data = src.read_bytes()
        out = decrypt_vfl(data)
    except (OSError, ValueError) as exc:
        sys.stderr.write('Error: {}\n'.format(exc))
        return 1

    dst.write_bytes(out)

    print('header (should start "VictorGSM.net Flash File"):')
    print(out[:HEADER_SIZE])
    print('Decrypted {} bytes -> {}'.format(len(out), dst))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

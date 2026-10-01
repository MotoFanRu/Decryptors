#!/usr/bin/env python3
'''
Decrypt VictorGSM.net Motorola .vfl flash files.

The VFL crypt routine is the DCPcrypt Blowfish implementation found in the
VictorGSM executable.

Usage:
	vfl_decrypt.py <file.vfl>            decrypt next to the source as <name>.decoded.bin
	vfl_decrypt.py <dir> [output_dir]    decrypt every *.vfl under <dir> into output_dir
	                                     (default: ./decrypted), keeping the directory tree
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

SRC_SUFFIX = '.vfl'
DST_SUFFIX = '.decoded.bin'
DEFAULT_OUT_DIR = 'decrypted'

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
	feedback = _ecb_block(key, True, b'\xff' * BLOCK_SIZE)
	out = bytearray()

	plain, feedback = _decrypt_full_blocks(
		data[:FULL_HEADER_SIZE], key, feedback
	)
	out += plain

	header_tail = data[FULL_HEADER_SIZE:HEADER_SIZE]
	keystream = _ecb_block(key, True, feedback)
	out += _xor(header_tail, keystream[:len(header_tail)])

	payload = data[HEADER_SIZE:]
	plain, feedback = _decrypt_full_blocks(payload, key, feedback)
	out += plain

	payload_tail_start = HEADER_SIZE + (len(payload) // BLOCK_SIZE * BLOCK_SIZE)
	payload_tail = data[payload_tail_start:]

	if payload_tail:
		keystream = _ecb_block(key, True, feedback)
		out += _xor(payload_tail, keystream[:len(payload_tail)])

	return bytes(out)


def job_list(target, out_dir):
	if target.is_file():
		yield target, target.with_name(target.stem + DST_SUFFIX)
		return
	for src in sorted(target.rglob('*')):
		if src.is_file() and src.suffix.lower() == SRC_SUFFIX:
			rel = src.relative_to(target)
			yield src, out_dir / rel.with_name(rel.stem + DST_SUFFIX)


def main(argv):
	if not 2 <= len(argv) <= 3:
		sys.stderr.write(__doc__)
		return 2

	target = Path(argv[1])
	out_dir = Path(argv[2]) if len(argv) == 3 else Path(DEFAULT_OUT_DIR)

	if not target.exists():
		sys.stderr.write('No such file or directory: {}\n'.format(target))
		return 2

	done = failed = 0
	for src, dst in job_list(target, out_dir):
		try:
			data = src.read_bytes()
			out = decrypt_vfl(data)
			dst.parent.mkdir(parents=True, exist_ok=True)
			dst.write_bytes(out)
		except (OSError, ValueError) as e:
			failed += 1
			sys.stderr.write('FAIL {}: {}\n'.format(src, e))
			continue
		done += 1
		print('Decrypted: {} => {}'.format(src, dst))

	if target.is_dir():
		print('Done: {} decrypted, {} failed'.format(done, failed))
	return 1 if failed else 0


if __name__ == '__main__':
	sys.exit(main(sys.argv))

#!/usr/bin/env python3

'''
Decrypt Motorola .vhs flex files (base64 -> Blowfish-CBC, key = SHA1 of a phrase).

Usage:
	vhs_decrypt.py <file.vhs>            decrypt next to the source as <name>_decrypted.hs
	vhs_decrypt.py <dir> [output_dir]    decrypt every *.vhs under <dir> into output_dir
	                                     (default: ./decrypted), keeping the directory tree
'''

import base64
import binascii
import hashlib
import sys
import warnings

from pathlib import Path

warnings.filterwarnings('ignore')

from cryptography.hazmat.primitives.ciphers import Cipher, modes

try:
	from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
except ImportError:  # older cryptography versions
	from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish

KEY_PHRASE = (
	b'Welcome to Motorola Service Software by VictorGSM.net '
	b'version 3.1.2 Email: info@victorgsm.net Web: www.victorgsm.net'
)
SRC_SUFFIX = '.vhs'
DST_SUFFIX = '_decrypted.hs'
DEFAULT_OUT_DIR = 'decrypted'


class DecryptError(Exception):
	pass


def _xor(a, b):
	return bytes(x ^ y for x, y in zip(a, b))


class LineDecryptor:
	def __init__(self, phrase=KEY_PHRASE):
		self._key = hashlib.sha1(phrase).digest()  # 160-bit key
		self._iv = self._ecb(True, b'\xff' * 8)    # DCPcrypt default IV (nil IV)

	def _ecb(self, encrypt, block):
		cipher = Cipher(Blowfish(self._key), modes.ECB())
		op = cipher.encryptor() if encrypt else cipher.decryptor()
		return op.update(block) + op.finalize()

	def decrypt(self, line):
		try:
			data = base64.b64decode(line, validate=True)
		except (binascii.Error, ValueError) as e:
			raise DecryptError('bad base64: {}'.format(e))
		cv = self._iv
		out = bytearray()
		full = len(data) // 8 * 8
		for i in range(0, full, 8):  # CBC
			block = data[i:i + 8]
			out += _xor(self._ecb(False, block), cv)
			cv = block
		if len(data) > full:  # residual bytes, no padding
			out += _xor(data[full:], self._ecb(True, cv))
		try:
			return out.decode('ascii')
		except UnicodeDecodeError:
			raise DecryptError('decrypted data is not ASCII (wrong key or not a flex file)')


def decrypt_file(src, dst, decryptor):
	try:
		text = src.read_text(encoding='utf-8-sig')
	except UnicodeDecodeError:
		raise DecryptError('not a text file')
	lines = []
	for num, raw in enumerate(text.splitlines(), 1):
		line = raw.strip()
		if not line:
			lines.append('')
			continue
		try:
			lines.append(decryptor.decrypt(line))
		except DecryptError as e:
			raise DecryptError('line {}: {}'.format(num, e))
	dst.parent.mkdir(parents=True, exist_ok=True)
	dst.write_text('\n'.join(lines) + '\n', encoding='ascii', newline='\n')


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

	decryptor = LineDecryptor()
	done = failed = 0
	for src, dst in job_list(target, out_dir):
		try:
			decrypt_file(src, dst, decryptor)
		except (DecryptError, OSError) as e:
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

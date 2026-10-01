#!/usr/bin/env python3
'''
Decrypt VictorGSM.net Motorola .vfl flash files.

The VFL crypt routine is the DCPcrypt Blowfish implementation found in the
VictorGSM executable.

Usage:
	vfl_decrypt.py <file.vfl>            decrypt next to the source as <name>.decoded.bin
	vfl_decrypt.py <dir> [output_dir]    decrypt every *.vfl under <dir> into output_dir
	                                     (default: ./decrypted), keeping the directory tree

VFL header format:

	0000-0017  56 69 63 74 6F 72 47 53 4D 2E 6E 65 74 20 46 6C 61 73 68 20 46 69 6C 65
				"VictorGSM.net Flash File"

	0018-001C  FF 01 00 FF FF
				unknown / ignored by this parser

	001D       02
				01 = V66
				02 = V60
				03 = T280
				04 = V70
				05 = T720
				06 = C33x

	001E       01
				01 = Full flash
				02 = Special flash (repair/reflash)
				03 = KJava
				04 = Language package only

	001F-0023  04 01 01 FF FF
				unknown / ignored by this parser

	0024-002F  CG0 record
				00 01 FF FF | 00 00 02 00 | 10 01 00 00
				^^^^^^^^^^^   ^^^^^^^^^^^   ^^^^^^^^^^^^
				record prefix    size          address

	0030-003B  CG1 record
				00 01 FF FF | 03 00 73 20 | 10 01 00 C8

	003C-0047  CG2 record
				00 00 00 00 | 00 00 00 00 | 00 00 00 00
				absent / empty often

	0048-0053  CG3 record
				00 01 FF FF | 00 01 20 72 | 10 00 80 00

	0054-005F  CG4 record
				00 01 FF FF | 00 20 72 48 | 10 2E E4 20

	0061       01
				01 - Neptune branch
				FF - Patriot branch

	0060-006B  Extended / RAMDLD metadata record (only if Neptune branch!)
				00 01 FF FF | 00 07 65 44 | 11 00 00 00
				^^^^^^^^^^^   ^^^^^^^^^^^   ^^^^^^^^^^^^
				prefix       RAMDLD size    RAMDLD address

	0064-...    29 C3 4B 32 ...
				RAMDLD data/code begins here for Patriot (header is 100 bytes)

	0096-...    29 C3 4B 32 ...
				RAMDLD data/code begins here for Neptune (header is 150 bytes)

	Next binary chunks for:
		RAMDLD
		CG0
		CG1
		CG2
		CG3
		CG4
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
DST_SUFFIX = '.dec.bin'
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


def parse_vfl_size_address(size, address):
	return (int(size.hex()), int.from_bytes(address, byteorder='big'))


def parse_vfl_decrypted_header(out):
	if len(out) < HEADER_SIZE:
		raise ValueError(' VFL header is shorter than the 100-byte header')

	magic = out[:0x18].decode('ascii', 'replace')
	bytes_magic = ' '.join('{:02X}'.format(b) for b in out[:0x18])
	print('    00-17   Magic: {}'.format(magic))
	print('    00-17   Bytes: {}'.format(bytes_magic))

	phone_code = out[0x1D]
	phone_name = {
		0x01: 'V66',
		0x02: 'V60',
		0x03: 'T280',
		0x04: 'V70',
		0x05: 'T720',
		0x06: 'C33x',
	}.get(phone_code)
	if phone_name is None:
		raise ValueError('Unknown phone type 0x{:02X} at 001D'.format(phone_code))
	print('    1D-1D   Phone: {:02X} ({})'.format(phone_code, phone_name))

	file_code = out[0x1E]
	file_name = {
		0x01: 'Full flash',
		0x02: 'Special flash (repair/reflash)',
		0x03: 'KJava',
		0x04: 'Language package only',
	}.get(file_code)
	if file_name is None:
		raise ValueError('Unknown file type 0x{:02X} at 001E'.format(file_code))
	print('    1E-1E   FType: {:02X} ({})'.format(file_code, file_name))

	branch_code = out[0x61]
	branch_name = {
		0x01: 'Neptune',
		0xFF: 'Patriot',
	}.get(branch_code)
	if branch_name is None:
		raise ValueError('Unknown branch flag 0x{:02X} at 0061'.format(branch_code))
	print('    61-61  Branch: {:02X} ({})'.format(branch_code, branch_name))

	print('    18-1C Ignored: {}'.format(
		' '.join('{:02X}'.format(b) for b in out[0x18:0x1D])
	))

	print('    1F-23 Ignored: {}'.format(
		' '.join('{:02X}'.format(b) for b in out[0x1F:0x24])
	))

	CGs = []

	if branch_code == 0x01:
		base = 0x60
		prefix = out[base + 1:base + 4]
		size = out[base + 4:base + 8]
		addr = out[base + 8:base + 12]
		print('    {:02X}-{:02X}     RDL: {} | {} | {}'.format(
			base + 1, base + 0x0C,
			' '.join('{:02X}'.format(b) for b in prefix),
			' '.join('{:02X}'.format(b) for b in size),
			' '.join('{:02X}'.format(b) for b in addr),
		))
		CGs.append(parse_vfl_size_address(size, addr))
	elif branch_code == 0xFF:
		print('    00-00     RDL: 01 FF FF | 00 16 38 40 | 11 01 00 00')
		CGs.append(parse_vfl_size_address(b'\x00\x16\x38\x40', b'\x11\x01\x00\x00'))

	for idx in range(5):
		base = 0x24 + idx * 0x0C
		prefix = out[base + 1:base + 4]
		size = out[base + 4:base + 8]
		addr = out[base + 8:base + 12]
		print('    {:02X}-{:02X}     CG{}: {} | {} | {}'.format(
			base + 1, base + 0x0C, idx,
			' '.join('{:02X}'.format(b) for b in prefix),
			' '.join('{:02X}'.format(b) for b in size),
			' '.join('{:02X}'.format(b) for b in addr),
		))
		CGs.append(parse_vfl_size_address(size, addr))

	return CGs

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
	jobs = list(job_list(target, out_dir))
	total = len(jobs)
	for index, (src, dst) in enumerate(jobs, 1):
		try:
			print('{:03d}/{:03d} Decrypting...'.format(index, total))
			print('    => {}'.format(src))
			data = src.read_bytes()
			out = decrypt_vfl(data)
			parse_vfl_decrypted_header(out)
			dst.parent.mkdir(parents=True, exist_ok=True)
			dst.write_bytes(out)
			print('    => {}\n'.format(dst))
		except (OSError, ValueError) as e:
			failed += 1
			sys.stderr.write('    FAIL {}: {}\n'.format(src, e))
			if 'Unknown' in str(e):
				return 1
			continue
		done += 1

	if target.is_dir():
		print('Done: {} decrypted, {} failed'.format(done, failed))
	return 1 if failed else 0


if __name__ == '__main__':
	sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""Extract RAMDLD and code-group SMG payloads from Motorola SHX files.

Usage:
	shx_unpack.py <file.shx> [output_dir]
	shx_unpack.py <directory> [output_dir]

For a single file, outputs are written next to the SHX unless output_dir is
provided. For a directory, all *.shx files are processed recursively into
output_dir (default: ./unpacked), retaining their directory structure.
"""

import sys
from pathlib import Path

SHX_HEADER_SIZE = 0x2000
SHX_CODE_GROUP_OFFSET = 0x3EC
SHX_CODE_GROUP_STRIDE = 0x1C
SHX_CODE_GROUP_CAPACITY = 5
SHX_GROUP_COUNT_OFFSET = 0x3B0
SRECORD_ADDRESS_LENGTH = {'1': 2, '2': 3, '3': 4}
SRECORD_TERMINATORS = {'7', '8', '9'}
SOURCE_SUFFIX = '.shx'
DESTINATION_SUFFIX = '.smg'
DEFAULT_OUTPUT_DIR = 'unpacked'


def _parse_srecord(line, line_number):
	if len(line) < 4 or line[:1] != b'S':
		raise ValueError('Invalid S-record on line {}'.format(line_number))

	try:
		record_type = chr(line[1])
		raw = bytes.fromhex(line[2:].decode('ascii'))
	except (UnicodeDecodeError, ValueError) as error:
		raise ValueError(
			'Invalid S-record on line {}'.format(line_number)
		) from error

	if not raw or len(raw) != raw[0] + 1 or sum(raw) & 0xFF != 0xFF:
		raise ValueError(
			'Invalid S-record length or checksum on line {}'.format(line_number)
		)

	address_length = SRECORD_ADDRESS_LENGTH.get(record_type)
	if address_length is None:
		return record_type, None
	if len(raw) < address_length + 2:
		raise ValueError('S-record address is truncated on line {}'.format(line_number))

	address = int.from_bytes(raw[1:1 + address_length], 'big')
	payload = raw[1 + address_length:-1]
	return record_type, (address, payload)


def _read_srecord_sections(shx):
	sections = []
	records = []
	srecord_stream = shx[SHX_HEADER_SIZE - 2:]
	for line_number, raw_line in enumerate(srecord_stream.splitlines(), 1):
		line = raw_line.strip()
		if not line:
			continue
		record_type, parsed = _parse_srecord(line, line_number)

		if record_type == '0':
			if records:
				sections.append(records)
				records = []
		elif record_type in SRECORD_ADDRESS_LENGTH:
			if record_type != '3':
				raise ValueError(
					'Expected S3 data records in SHX, found S{} on line {}'
					.format(record_type, line_number)
				)
			if parsed is not None:
				records.append(parsed)
		elif record_type in SRECORD_TERMINATORS:
			if records:
				sections.append(records)
				records = []

	if records:
		sections.append(records)
	if not sections:
		raise ValueError('SHX contains no S3 data records')
	return sections


def _extract_range(records, start, end):
	if end < start:
		raise ValueError('Invalid SHX data address range')

	output = bytearray(end - start + 1)
	cursor = start
	for address, payload in sorted(records):
		record_end = address + len(payload)
		if record_end <= cursor or address > end:
			continue
		if address > cursor:
			raise ValueError('SHX S-record data has a gap at 0x{:08X}'.format(cursor))

		copy_start = max(cursor, address)
		copy_end = min(end + 1, record_end)
		output[copy_start - start:copy_end - start] = (
			payload[copy_start - address:copy_end - address]
		)
		cursor = copy_end
		if cursor > end:
			return bytes(output)

	raise ValueError('SHX S-record data ends before 0x{:08X}'.format(end))


def _code_group_ranges(shx):
	group_count = shx[SHX_GROUP_COUNT_OFFSET]
	if not group_count:
		raise ValueError('SHX header has no code-group count')

	if group_count > SHX_CODE_GROUP_CAPACITY + 1:
		raise ValueError('SHX header declares too many code groups')

	ranges = []
	for index in range(SHX_CODE_GROUP_CAPACITY):
		offset = SHX_CODE_GROUP_OFFSET + index * SHX_CODE_GROUP_STRIDE
		start = int.from_bytes(shx[offset:offset + 4], 'little')
		end = int.from_bytes(shx[offset + 4:offset + 8], 'little')
		if start == end == 0:
			continue
		if end < start:
			raise ValueError('Invalid CG{} address range in SHX header'.format(index))
		ranges.append((index, start, end))
	return ranges


def unpack_shx(shx):
	if len(shx) < SHX_HEADER_SIZE:
		raise ValueError('SHX file is shorter than its 0x2000-byte header')

	sections = _read_srecord_sections(shx)
	outputs = {}
	ramdld_records = sections[0]
	ramdld_start = min(address for address, _ in ramdld_records)
	ramdld_end = max(
		address + len(payload) - 1 for address, payload in ramdld_records
	)
	outputs['R'] = _extract_range(ramdld_records, ramdld_start, ramdld_end)

	for group_index, start, end in _code_group_ranges(shx):
		matching_sections = []
		for section_index, records in enumerate(sections[1:], 1):
			try:
				payload = _extract_range(records, start, end)
			except ValueError:
				continue
			section_start = min(address for address, _ in records)
			section_end = max(
				address + len(data) - 1 for address, data in records
			)
			extra_bytes = section_end - section_start - (end - start)
			matching_sections.append((extra_bytes, section_index, payload))

		if not matching_sections:
			raise ValueError(
				'No S-record section contains the full address range for CG{}'
				.format(group_index)
			)
		_, _, payload = min(matching_sections, key=lambda match: match[:2])
		outputs[str(group_index)] = payload

	return outputs


def _jobs(target, output_dir):
	if target.is_file():
		if target.suffix.lower() != SOURCE_SUFFIX:
			raise ValueError('Input file must have a .shx extension')
		directory = output_dir if output_dir is not None else target.parent
		yield target, directory, target.stem
		return

	for source in sorted(target.rglob('*')):
		if source.is_file() and source.suffix.lower() == SOURCE_SUFFIX:
			relative = source.relative_to(target)
			yield source, output_dir / relative.parent, source.stem


def main(argv):
	if not 2 <= len(argv) <= 3:
		sys.stderr.write(__doc__)
		return 2

	target = Path(argv[1])
	if not target.exists():
		sys.stderr.write('No such file or directory: {}\n'.format(target))
		return 2
	if not target.is_file() and not target.is_dir():
		sys.stderr.write('Input must be an SHX file or directory\n')
		return 2

	output_dir = Path(argv[2]) if len(argv) == 3 else None
	if target.is_dir() and output_dir is None:
		output_dir = Path(DEFAULT_OUTPUT_DIR)

	done = failed = 0
	jobs = list(_jobs(target, output_dir))
	for index, (source, destination_dir, stem) in enumerate(jobs, 1):
		try:
			print('{:03d}/{:03d} Unpacking...'.format(index, len(jobs)))
			shx = source.read_bytes()
			outputs = unpack_shx(shx)
			destination_dir.mkdir(parents=True, exist_ok=True)
			for group_name, payload in outputs.items():
				destination = destination_dir / (
					'{}_{}.smg'.format(stem, group_name)
				)
				destination.write_bytes(payload)
				print('    => {}'.format(destination))
		except (OSError, ValueError) as error:
			failed += 1
			sys.stderr.write('    FAIL {}: {}\n'.format(source, error))
			continue
		done += 1

	if target.is_dir():
		print('Done: {} unpacked, {} failed'.format(done, failed))
	return 1 if failed else 0


if __name__ == '__main__':
	sys.exit(main(sys.argv))

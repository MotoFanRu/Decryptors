#!/usr/bin/env python3
"""Analyze SHX code-group boundaries for overlapping and suspicious S-record bytes.

Usage:
	shx_analize.py <file.shx>
	shx_analize.py <directory>
"""

import sys
from pathlib import Path

SHX_HEADER_SIZE = 0x2000
SHX_GROUP_COUNT_OFFSET = 0x3B0
SHX_CG_HEADER_OFFSET = 0x3EC
SHX_CG_HEADER_STRIDE = 0x1C
SHX_CG_CAPACITY = 5
SREC_DATA_SIZE = 64
SRECORD_ADDRESS_LENGTH = {'0': 2, '3': 4, '7': 4}
SREC_FILL_PATTERN = bytes.fromhex('EC 7A D5 2F 64 DD 66 A1')


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

	if not raw or len(raw) != raw[0] + 1:
		raise ValueError('Invalid S-record length on line {}'.format(line_number))
	if sum(raw) & 0xFF != 0xFF:
		raise ValueError('Invalid S-record checksum on line {}'.format(line_number))

	address_length = SRECORD_ADDRESS_LENGTH.get(record_type)
	if address_length is None:
		return record_type, None
	if len(raw) < address_length + 2:
		raise ValueError('S-record address is truncated on line {}'.format(line_number))

	address = int.from_bytes(raw[1:1 + address_length], 'big')
	payload = raw[1 + address_length:-1]
	return record_type, (address, payload)


def _read_sections(shx):
	sections = []
	records = []
	stream = shx[SHX_HEADER_SIZE - 2:]
	for line_number, raw_line in enumerate(stream.splitlines(), 1):
		line = raw_line.strip()
		if not line:
			continue
		record_type, parsed = _parse_srecord(line, line_number)
		if record_type == '0':
			if records:
				sections.append(records)
				records = []
		elif record_type == '3':
			if parsed is not None:
				address, payload = parsed
				records.append((address, payload, line_number))
		elif record_type == '7':
			if records:
				sections.append(records)
				records = []
	if records:
		sections.append(records)
	if not sections:
		raise ValueError('SHX contains no S3 data records')
	return sections


def _read_code_groups(shx):
	group_count = shx[SHX_GROUP_COUNT_OFFSET]
	if not group_count:
		raise ValueError('SHX header has no code-group count')
	if group_count > SHX_CG_CAPACITY + 1:
		raise ValueError('SHX header declares too many code groups')

	groups = []
	for index in range(SHX_CG_CAPACITY):
		offset = SHX_CG_HEADER_OFFSET + index * SHX_CG_HEADER_STRIDE
		start = int.from_bytes(shx[offset:offset + 4], 'little')
		end = int.from_bytes(shx[offset + 4:offset + 8], 'little')
		if start == end == 0:
			continue
		if end < start:
			raise ValueError('Invalid CG{} address range'.format(index))
		groups.append((index, start, end))
	return groups


def _compare_section(records, start, data):
	match_count = available_count = 0
	end = start + len(data)
	for address, payload, _ in records:
		overlap_start = max(start, address)
		overlap_end = min(end, address + len(payload))
		if overlap_start >= overlap_end:
			continue
		expected = data[overlap_start - start:overlap_end - start]
		actual = payload[
			overlap_start - address:overlap_end - address
		]
		available_count += len(expected)
		match_count += sum(left == right for left, right in zip(expected, actual))
	return match_count, available_count


def _is_fill_pattern(data):
	return bool(data) and data == (
		(SREC_FILL_PATTERN * ((len(data) + len(SREC_FILL_PATTERN) - 1)
			// len(SREC_FILL_PATTERN)))[:len(data)]
	)


def _find_boundary_records(sections, groups):
	boundaries = []
	for left in groups:
		for right in groups:
			if left[2] + 1 == right[1]:
				boundaries.append((left, right))

	findings = []
	for left, right in boundaries:
		boundary = right[1]
		for section_index, records in enumerate(sections):
			for record_index, (address, payload, line_number) in enumerate(records):
				record_end = address + len(payload)
				if not address < boundary < record_end:
					continue
				if not left[1] <= address <= left[2]:
					continue
				if (
					record_index == 0
					and address == boundary - boundary % SREC_DATA_SIZE
					and _is_fill_pattern(payload[:boundary - address])
				):
					continue

				overlap_start = boundary
				overlap_end = min(record_end, right[2] + 1)
				crossing_bytes = payload[
					overlap_start - address:overlap_end - address
				]
				candidates = []
				for candidate_index, candidate_records in enumerate(sections):
					if candidate_index == section_index:
						continue
					common, available = _compare_section(
						candidate_records, overlap_start, crossing_bytes
					)
					if available:
						candidates.append((common, available, candidate_index))

				best_match = max(candidates, default=(0, 0, None))
				match_count, available_count, candidate_index = best_match
				nonmatching = available_count - match_count
				unverified = len(crossing_bytes) - available_count
				is_fill = _is_fill_pattern(crossing_bytes)
				findings.append({
					'left': left,
					'right': right,
					'section': section_index + 1,
					'line': line_number,
					'address': address,
					'boundary': boundary,
					'crossing_bytes': crossing_bytes,
					'match_count': match_count,
					'available_count': available_count,
					'candidate_section': (
						candidate_index + 1 if candidate_index is not None else None
					),
					'nonmatching': nonmatching,
					'unverified': unverified,
					'is_fill': is_fill,
					'suspicious': bool(nonmatching and not is_fill),
				})
	return findings


def analyze_shx(shx):
	if len(shx) < SHX_HEADER_SIZE:
		raise ValueError('SHX file is shorter than its 0x2000-byte header')
	groups = _read_code_groups(shx)
	sections = _read_sections(shx)

	overlaps = []
	for index, first in enumerate(groups):
		for second in groups[index + 1:]:
			start = max(first[1], second[1])
			end = min(first[2], second[2])
			if start <= end:
				overlaps.append((first, second, start, end))

	return {
		'groups': groups,
		'sections': sections,
		'overlaps': overlaps,
		'boundary_records': _find_boundary_records(sections, groups),
	}


def _format_report(path, analysis):
	lines = ['{}'.format(path)]
	for first, second, start, end in analysis['overlaps']:
		lines.append(
			'  ERROR: CG{} and CG{} descriptors overlap at 0x{:08X}-0x{:08X}'
			.format(first[0], second[0], start, end)
		)

	for finding in analysis['boundary_records']:
		left = finding['left']
		right = finding['right']
		severity = 'WARNING' if finding['suspicious'] else 'INFO'
		details = (
			'  {}: S-record in section {} (line {}) crosses CG{} -> CG{} '
			'boundary 0x{:08X} at record 0x{:08X}; {} bytes extend into CG{}'
		).format(
			severity, finding['section'], finding['line'], left[0], right[0],
			finding['boundary'], finding['address'],
			len(finding['crossing_bytes']), right[0]
		)
		if finding['available_count']:
			details += (
				'; matches section {} bytes at {}/{} positions'
			).format(
				finding['candidate_section'], finding['match_count'],
				finding['available_count']
			)
		if finding['nonmatching']:
			details += '; {} bytes disagree with the neighboring CG'.format(
				finding['nonmatching']
			)
		if finding['unverified']:
			details += '; {} bytes cannot be independently compared'.format(
				finding['unverified']
			)
		if finding['is_fill']:
			details += '; crossing data is the known S-record fill pattern'
		elif finding['suspicious']:
			details += '; suspicious boundary bytes (possible legacy garbage)'
		else:
			details += '; no unexplained neighboring bytes detected'
		lines.append(details)

	if not analysis['overlaps'] and not analysis['boundary_records']:
		lines.append('  No descriptor overlaps or cross-CG S-records found.')
	return '\n'.join(lines)


def _find_files(target):
	if target.is_file():
		if target.suffix.lower() != '.shx':
			raise ValueError('Input file must have a .shx extension')
		return [target]
	return sorted(
		path for path in target.rglob('*')
		if path.is_file() and path.suffix.lower() == '.shx'
	)


def main(argv):
	if len(argv) != 2:
		sys.stderr.write(__doc__)
		return 2

	target = Path(argv[1])
	if not target.exists():
		sys.stderr.write('No such file or directory: {}\n'.format(target))
		return 2
	if not target.is_file() and not target.is_dir():
		sys.stderr.write('Input must be an SHX file or directory\n')
		return 2

	try:
		files = _find_files(target)
	except ValueError as error:
		sys.stderr.write('{}\n'.format(error))
		return 2
	if not files:
		print('No .shx files found.')
		return 0

	failed = findings = 0
	for path in files:
		try:
			analysis = analyze_shx(path.read_bytes())
		except (OSError, ValueError) as error:
			failed += 1
			sys.stderr.write('{}: ERROR: {}\n'.format(path, error))
			continue
		print(_format_report(path, analysis))
		findings += bool(
			analysis['overlaps']
			or any(record['suspicious'] for record in analysis['boundary_records'])
		)

	print('Analyzed {} SHX file(s); {} with findings; {} failed.'.format(
		len(files), findings, failed
	))
	return 1 if failed else 0


if __name__ == '__main__':
	sys.exit(main(sys.argv))

# Decryptors

A collection of various decryptors for encrypted firmware formats and other files.

## Dependencies

```
pip install cryptography
```

## VFL to SHX

Run `vfl_decrypt.py <file.vfl>` to decrypt a VFL firmware and package its code
groups as an S-record `.dec.shx` file next to the input. For a directory, run
`vfl_decrypt.py <directory> [output_dir]`; the default output directory is
`decrypted`.

Code-group checksums use the RAMDLD flash map at offset `0x100` in the
second-layer-decrypted RAMDLD image. The decrypted code groups are placed into
a 16 MiB `FF`-filled flash image at their VFL addresses (Patriot addresses are
relative to `0x10000000`; Neptune addresses are absolute). Each RAMDLD map
range is then divided across its code groups, and each checksum is the
16-bit bytewise sum from that group's range start through its assigned range
end. The first eight bytes are treated as `FF` for CG0's checksum. S-record
payload bytes remain unchanged; only the checksum calculation uses the
second-layer-decrypted code groups.

The final S7 record stores the 16-bit bytewise sum of all preceding SHX bytes
in its address field (prefixed by `4353`). It is recalculated for each output,
so changing the header date also changes this checksum.

## SHX to SMG

Run `shx_unpack.py <file.shx>` to extract the RAMDLD and each code group into
separate `.smg` files next to the SHX. Output names use `_R.smg` for RAMDLD
and `_<CG number>.smg` for code groups. For a directory, run
`shx_unpack.py <directory> [output_dir]`; the default output directory is
`unpacked`.

## SHX boundary analysis

Run `shx_analize.py <file.shx>` or `shx_analize.py <directory>` to scan SHX
files for overlapping code-group descriptors and S3 records that cross
adjacent code-group boundaries. For crossing records, it compares the bytes
inside the next group's address range with other S-record sections and flags
unmatched bytes as suspicious boundary data. Normal alignment/padding crossings
are reported as informational unless independently compared bytes disagree.
This is a diagnostic heuristic; it reports evidence and does not modify SHX files.

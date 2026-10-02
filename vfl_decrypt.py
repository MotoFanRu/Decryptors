#!/usr/bin/env python3
'''
Decrypt VictorGSM.net Motorola .vfl flash files.

The VFL crypt routine is the DCPcrypt Blowfish implementation found in the
VictorGSM executable.

Usage:
	vfl_decrypt.py <file.vfl>            create <name>.dec.shx next to the source
	vfl_decrypt.py <dir> [output_dir]    convert every *.vfl under <dir> into output_dir
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

import base64
import hashlib
import struct
import sys
import warnings
import zlib
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

# Compressed Tbl1-Tbl4 and Key DWORDs from fl_decr.asm.
_SMG_BLOWFISH_TABLES_B85 = (
	'c-jF#5WnwgYhknLBr8Y)HrZ)|&=q|9xkEA@p9`60tpy<)=5J|-VF?>dsW6n(C_r|A%FAgvye%K!%lxeq;(Ax?*xg8%q!S`Q(pPPg'
	'r>S`5HQTuuE)!_H4cUPb0)YvrHQ445-CKmnz0&Zyh)qfomTw{;CVIlakdHlUX)9MgJ@DCE&nvtv?$d_))QiVN)@5?gXkMYZQJSL0'
	'K^ig_by=Pt>9(aygm7f@G<_||r9+PW5rDrnlvQ3#=g&M3OAPUA6+3_b&MVhSIR5W9cuQwKbW*G(^aC$ybk5moQvL(SNfGT(UgZN$'
	'2Oah=J~?pA1<z~M#Z(bsGcT$tYx9dFOCk;8ktPu->%#r-uU@>i$|nIoXxPby7fwhlWWY(j<*|a+>F!`c;LtvS-HLr&J>Z$5Be6PO'
	'QDMOr`}zvJ<#%0qthQHI7|iT@yhsO1X0RIF#>{J@d9%%d<Jq^4M)q2x)gqcIH@d(e){`f~b$0A|M<}NJlkol1Wb`47{LK>y!`xq*'
	'4UkkDgFSupSqr(4V)9lP=g_RhY)Zz#LFM_QLxx2xet!lGMU|^sIq09>u6Wp4A064I7@0E`$R|tt8FA_VA6)%xKK<Ey!C37}7ziq6'
	'Te2ocBoS)qGqib%n5j%>T1@xcf^<Vnj2m9wmu-T^@|?vqL=Iu~s-y&SjbkmRy|UA_3iMGU8|%>1CNGWLU~B_~)1`10CniMxz5okY'
	'Qr65XRB{p1HC+GV1tZFLR|?{o8fuJDu}Jg7kR+3C7wCst&)v~_98Am|Ai)6l3)`7oMR6I=H4D1-1oEfFp(CTpDh+KZ@Ja!t7G}xY'
	'GW~o3#EO5jt9K|zEd!Vb;-5e?1JKZzQis}=Mm(9=gjBY}48zrQy!js@Aq<2x)-gu)g+h>>Ta_=jP$)ULfdnw>{tLXfdtHW!P0)#2'
	'Np=x9tTzHY)_qi@zb<8eO!m?JQG`1(FH5H0uw#jFM%6$t3F2BI6;C+opGIO<g^{u``rsGbs%F>*E_jO#4QLbC$=Nj9_F%T86`H%g'
	'lEpSIHIt-D7`Ckp@7CBpd;nD#&xOQA@Z>HK$;`O0ui9~Yn}r+HkUtVf13kn;aWgZqIFA+rlkW|tC(ilMfl}r9TmqRVKE(Wk2sT<?'
	'ZsfuCxzLej8&V=Xd+#3MNdWa08=`nNEy+&rRT=2=PM|HJZ2nb2md3k2%-Z2yvXvdI>Qozr2?uw^?=|Y*Nj$2a(X`b&HIwV1oCdm~'
	'3TB@}4g~rCt*^#X2AXF6d`HHT?;544mcq_b0j%5R`U0&@`78ewRlGY69NC2h^Q2uci_=Hzucv)8??EQy7xPSJXgxJde#oy;c}^m!'
	'AHyAu;)b)o<XYbbhH3<BH+M`h!uB;R)^GS`ky$#5N3Wc>`1yVk+1|6>x=ZqzjbzWeRO>WYP+6_PsfjDXi(kB$A+BZ%R}ID?;Td=l'
	')NXxqGm0Sz$lmSRGhO3Jaz`Ss;c`<$#cB}g1gkB}Am#zj`2Sdp>rjgUbIjy?NFwI8ey)iK1my(bNM|a0GSQC|P?A+7Zayy@_BAWv'
	'1sdMVI{*hYh^xBIZ1AGOkP`^2Guh-4!r0b!T}=B<c_KdZeF?PUTXy#xi~p1vYSfHyV76nVuJy2d7LV~ys?s?Ki!lQp7pfmQ?{^i9'
	'^}kpKU=IPh$f}%G-D8a3Blr`JdP)<XZ$pw9*<C?1y1ISC8Nv<tp*>hWemQwia?v2&T&7%Yc)Q3)M*p9ACa@Um&EkcY?z(>b29k@u'
	'=nQL&gDl5}nAzg@wKSPIo<`XN%$j8!>N9-F**I#FK{OP!QwZ)zw{EZlA&(@0?2)%8E#@UE26DweOr!G8?JocPj9!HvgcWcFrQRlZ'
	'`zLCF!BC5EZ^}ul?7Ng{YXgX0S|(wcy)yqh+M~hFczTrLu;$JqyNdJGet|kclAnh-HkzVajleS5{>6H)0yJD(>ADnE&U2*6AP{by'
	'B(R*;%YDFus1h<S_&m`rP^0N5hn+i0br45dtdBFAsA%}QgnxnQ@loS3)j;L6CXh8pM9JJ!af`MQ!;^31&dUGcTRntc0?fK0VOva_'
	'Kv)M>QGIP`<^2Y~YEolra{}KLHI7=I7V()wAtwazTnEc+b#EHh61jbhzQEA`Y%f0wN=j*g8Co(#73gi60#lo(V7Hi`Q(vweDM=EN'
	'ARs;Ig?!XMm#jma6b#l#Yq&X+7-b-vw8@r!G~It$Z6{0*KB}D8Ej+atU!=v?UxqE>j1L78edBFfb!~w6GrD>(%|OR=p8xP~_EQFu'
	'mK$yizxN%+o;6?BpCedw)C(aaRf6MxJ`GU4bhw&XLL^AAsTbS*TLt<H7)^ZJ4#0k}3<)((W1y5#84I5C2di1f%Jn*BNHw5{1fKX='
	'Epe_9ekebd2{lB&Hutl_nYJ%K12B|aTbY2Or$%m$TC2C6>Vr~ZPGdhz>w#9ImS0E<!!%|uKi|AIi78U-O=d2+fr?%M-51~T+n4^Y'
	'cy}lA3L4q-i|FgoY6CG7Cu@YgPy-n)pZLP0HV}fghSw1>yS}*J<i5Pk)j8s_PsHk9oK)kaItFCgt+e<u6(%%uX)ybll$iToFAxpY'
	'u^|~&o!r^gooBZVa)wJKlyJHvT0hG#SZV2j$1ry`cE&HBpKGUNHobOaoS&Iw5q87@2N8+vY5`C3Ek7|B5dcvkWMz$1l3Es0>842='
	'lK@T<3>)0))`Tut9{@42ouczN*GirOn)QIJcq(OkAcMWlxuWM{kFb5sD2H4!q1c7l1xvb;wK=|Q@nxw-bq`cqh`%#+fVa5i6IM%~'
	'tTn>MK0tBWP8d@&aZll!ZLk1zhczJ@6KUwjt`fa>@r#f(IqyX$ln8Caiy!Bsk5eLU3(eI>S8X7J8<1mExweTajhVPqDnNaH$pY+$'
	'<h<Lmec&mVVXgI|N(Rp{FwykHGdh0Zo3&}<oC}VuE}IDBY7k;pbVYg(*kOQ7oti)EhFD7)R0NHX1kSFP;tOB*-1pRX;7`PDXk-g*'
	')P>f2Iyb`ljy{wUAPBT2#X)ZK29wbgHtukg1aQppoS9T$OC4WzfzLHDjNbK9-7eR)kOO7F)hGtebDsPHu4%q_b8&*{LAF$X0b(L-'
	'`9jR-jxA(#P;4%3$4lAvKoB{decRV1gYcmT=Qmlv$sn4JfkU%wy{HLk6VF*C0a|7=-(+k#dc-PxhKZzZvv*6(;|Jd18s*J84hIeB'
	'nES{b=@)Q9c~%R^@yjDm<QBaRPIH&y><)Q3@&Cn_Xu5&&#GgHl5FoJD9dlswgY21Y#{t_^0s;_a=JR6N%78pZU5k&k4H`(J1q^+F'
	'7_^1J^>@>r<VTflxUHWXpAt;|k4}AJ({0ZX#WVsrxHjRFav4g9ebiD5nb{&;G3#x}X=^L}Y=+`+eWBCYG|bbg;aXkW$`J&ArBrQL'
	'Md_akE*q^`1P@*10A`lQNYg|5F{?Bu;1LSz|APXBKP5@1SpN@51s3)slCZbaIp5%DebR`07H-unQK2z3CuWLwL6(l{AxjC4V~nOc'
	'qr4W(`jnMx&aNm8#yz&b`^We{0TX$KD^^&>;9RBsTfG1=d9w3BLEUEtnVT=+!>bTljR)-F7JTQuXiIrltil0$B@<C7EGDqRB0T%U'
	'$4MQ>tfqC_aeRg}d?OGx`d48b$TR}!2AgA*@5o;oE>df<l%(X+-ahpPeq2C=35`gvIhzVWkR{U#z?M7H^{I|g<9mkSKw2iXp_OP8'
	'rcMmP<GTC8!n6~N7LS|q82tT>)xNy};%kt)??;AwH+}3Pl0ZfC<b%4p$Cj19Jynss^@>Lv_r;BU4`Ue5Yvci`x!U;TKRXoiBM#I+'
	'uOQ7PH9=#tE`C#sqa?pwso4>GyF$shfdqAwHL9GLmM}L_B!@&un0QrN;sy3{V}XKglTz4n9dL&X$ldP|%gJ2uK*oRYMdnJWXZ4At'
	'mM64C4=AKpGxogT5%ntGE=p#G7P%bg3PIlzZE<9>%3FSL579>Uvaz?R^+;`<)(6kf_MwJlj*T$#9U)ZPfe9uW2cr9Y)&mY)Y{Sw('
	'h$j|*6o$0HZCn=ZfnTgYr=N$0Vv+r=;=ApkFdKw#2C?TA@aO3(Z7<_{of5L{9Q41?>D^z`$XC#jO~G<i{(tIVS+gUW2Rf$CUqLpS'
	'*N4XSAmZ&XCE%O}F(IMI%+tcxKNtX7943U4i_F8(>5gq-_Iq#RlE!5%CWE|-+W4Qq?do>ynI7EA=_lW0DHS-77|KbrL2q+&FWBER'
	'=ylAkPvOb=ODObfaMP#-a!|2s<5NE6(kcz-6D|Oxxg$)QfnQ+<;#Xbdo6cyMsCbe)xbCh`A^KQRc|kRPQhLn1mnbL&pm>rmumW1V'
	'@;3kow>n^io>xKkd_gR%4PhMu4R(@97yi<We=d+qCfNX;bv)y#rmXQ2){2n^E$#Q_CcaNgAAlOQ&RG*6zK(Zx>5u_@CsGl#YpQlH'
	'?Msve?2h(CWi~~X8LD6MimFl5YCGtE)KQC%)B@<P03P9@`by1k?e8BRQ`~3-FW>1gm*SgvbPHm!U7O8Rz$>uIQWq>a+#V}5EyNx|'
	'bF?j_yRES4Ej*=9o_>DBL;E%nxi#TI{x>`+x<Q`_{mgWvjSY5Gzi~Yhw;QV=bzr5^j^U2U(DKN3YF`;>zrGz&gZSUD;9V`%Y|MQt'
	'1*RDliV_IpDJF-|?=~QC365cm%U4-e;p7_uk-~U1AX#)NM=VtM<xE*SbiZP!ZI6i(lEGj!v?_1scqgLviO>}E##9Q--4swEEL8_v'
	'b}__pyjhIgt96@D+h`kFGr~>=UL<w;?Wwn6N81=N2-9z8>;ipE02J^?2uhveG&0hd`7d45{2^$H+Gn|el%FC9MvbFv1gj9g{=R3x'
	'w6kkp?Bna{_M95PHqCk_*R}b_d~%M#o=XLdhl^f94tzK=YH+L_c)L1qx9x8wxoy{&+e%O>=~UC>#5Wnh)AKU9)QZFVS~Niwhf;?m'
	'#g30`h(fLYlTQX!Z0;G7*WOJ12+STE^bw?d7`v9=7A#S)Yk}TJ7Y&4A-cBl>QF|@)a!i2fP-be<p2aer6uKUWK|8IUaas286WFg7'
	'sjE^|CxS7rv%G8s>`cCaBl>7v<I{?kr0dyA$!z&kLL)KJ&Q%2~xRcI#<L2Qs5N!YIBsF)iRj-f&(qsV}GWuXyu7S=Yjfa1jA~ngi'
	's}f_O|GCU^N!_ij?;x9}qQqxzrQwdEb$-2K(HSlD;zSBBYt1}9v!=sJP}EKG!QS8u!`pBR-3>#r<8b?3gR0}CLUM~S-6iMXnD0gw'
	'0*<uA*7upzBQ3+a(c`6W6i_;E1tsS|EsV*;&Yf*y)kfMo*)A+T+qfARP5$sLpJw2Hf7KYpP9F>mDPSbh=Vz^KvnE~SgvJa~D$T=T'
	'!ECBy@pF%iR`7l'
)
_SMG_BLOWFISH_WORDS = struct.unpack(
	'>1040I',
	zlib.decompress(base64.b85decode(_SMG_BLOWFISH_TABLES_B85)),
)
_SMG_BLOWFISH_SBOXES = tuple(
	_SMG_BLOWFISH_WORDS[index * 256:(index + 1) * 256]
	for index in range(4)
)
_SMG_BLOWFISH_KEY = _SMG_BLOWFISH_WORDS[1024:]

SRC_SUFFIX = '.vfl'
DST_SUFFIX = '.dec.shx'
DEFAULT_OUT_DIR = 'decrypted'

HEADER_SIZE = 0x64
FULL_HEADER_SIZE = 0x60
BLOCK_SIZE = 8
SHX_HEADER_SIZE = 0x2000
SREC_DATA_SIZE = 64
FLASH_IMAGE_SIZE = 0x1000000
RAMDLD_FLASH_MAP_OFFSET = 0x100
RAMDLD_FLASH_MAP_ENTRIES = 8

SHX_BRANCH_METADATA = {
	0x01: {
		'version': b'3.50',
		'ramdld': bytes.fromhex('06 11 FF 3B 07 11'),
		'group_table': bytes.fromhex('02 02 03 FF 00 03 72 5A A8'),
		'platform': bytes.fromhex('B1 01 02 02 06 50'),
		'ma_group_info': bytes.fromhex('06 04'),
		'cg_entry_point': 0x10010C00,
		'cg_header_middle': bytes.fromhex('00 00 00 B1'),
		'cg_header_tail': bytes.fromhex('01 02 06 50 00 01 01'),
		'ramdld_entry_adjustment': 0,
	},
	0xFF: {
		'version': b'2.00',
		'ramdld': bytes.fromhex('01 11 FF 7F 03 11'),
		'group_table': bytes.fromhex('01 02 03 FF 00 03 14'),
		'platform': bytes.fromhex('B1 01 01 02 06 30'),
		'ma_group_info': bytes.fromhex('01 01'),
		'cg_entry_point': 0x10010C00,
		'cg_header_middle': bytes.fromhex('00 00 00 B1'),
		'cg_header_tail': bytes.fromhex('01 02 06 30 00 01 01'),
		'ramdld_entry_adjustment': 0x1A0,
	},
}

SHX_PHONE_METADATA = {
	(0xFF, 0x04): {
		'version': b'3.50',
		'cg_header_tail': bytes.fromhex('01 02 06 0C 23 01 01'),
		'group_tables': {
			0x01: bytes.fromhex('01 02 03 FF 00 03 67 13 B7'),
		},
	},
}

SREC_FILL_PATTERN = bytes.fromhex('EC 7A D5 2F 64 DD 66 A1')
SHX_CG_HEADER_OFFSET = 0x3EC
SHX_CG_HEADER_STRIDE = 0x1C
SHX_CHECKSUM_PREFIX = 0x43530000


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


def _decrypt_smg(data):
	out = bytearray(data)
	for offset in range(0, len(data) - len(data) % BLOCK_SIZE, BLOCK_SIZE):
		left, right = struct.unpack_from('>II', data, offset)
		for key_word in reversed(_SMG_BLOWFISH_KEY):
			left ^= key_word
			value = (
				(_SMG_BLOWFISH_SBOXES[0][left >> 24]
					+ _SMG_BLOWFISH_SBOXES[1][(left >> 16) & 0xFF])
				& 0xFFFFFFFF
			)
			value ^= _SMG_BLOWFISH_SBOXES[2][(left >> 8) & 0xFF]
			value = (
				value + _SMG_BLOWFISH_SBOXES[3][left & 0xFF]
			) & 0xFFFFFFFF
			right ^= value
			left, right = right, left

		left, right = right, left
		right ^= 0xE229290E
		left ^= 0x3D042139
		struct.pack_into('>II', out, offset, left, right)

	return bytes(out)


def _parse_ramdld_flash_map(ramdld_image, flash_base):
	ranges = []
	for index in range(RAMDLD_FLASH_MAP_ENTRIES):
		offset = RAMDLD_FLASH_MAP_OFFSET + index * 8
		if offset + 8 > len(ramdld_image):
			raise ValueError('RAMDLD is too short to contain its flash map')

		start = int.from_bytes(ramdld_image[offset:offset + 4], 'big')
		end = int.from_bytes(ramdld_image[offset + 4:offset + 8], 'big')
		if start == end == 0xFFFFFFFF or start == end == 0:
			ranges.append(None)
			continue

		if not (
			flash_base <= start <= end < flash_base + FLASH_IMAGE_SIZE
		):
			break
		ranges.append((start, end))
	else:
		return ranges

	return ranges


def _checksum_code_groups_from_ramdld(ramdld_data, code_chunks, flash_base):
	ramdld_image = _decrypt_smg(ramdld_data)
	map_ranges = _parse_ramdld_flash_map(ramdld_image, flash_base)
	map_groups = [[] for _ in map_ranges]

	for chunk in code_chunks:
		descriptor_index, _, address, _ = chunk
		matches = [
			index for index, address_range in enumerate(map_ranges)
			if address_range is not None
			and address_range[0] <= address <= address_range[1]
		]
		exact_matches = [
			index for index in matches
			if map_ranges[index][0] == address
		]
		if exact_matches:
			map_index = exact_matches[0]
		elif matches:
			map_index = matches[0]
		else:
			raise ValueError(
				'Code group {} is not covered by the RAMDLD flash map'
				.format(descriptor_index - 1)
			)
		map_groups[map_index].append(chunk)

	flash_image = bytearray(b'\xFF' * FLASH_IMAGE_SIZE)
	decrypted_groups = {}
	for descriptor_index, size, address, encrypted_data in code_chunks:
		image_data = _decrypt_smg(encrypted_data)
		image_offset = address - flash_base
		if image_offset < 0 or image_offset + size > FLASH_IMAGE_SIZE:
			raise ValueError(
				'Code group {} is outside the 16 MiB flash image'
				.format(descriptor_index - 1)
			)
		flash_image[image_offset:image_offset + size] = image_data
		decrypted_groups[descriptor_index] = image_data

	checksum_ranges = {}
	for address_range, groups in zip(map_ranges, map_groups):
		if address_range is None or not groups:
			continue

		map_start, map_end = address_range
		for group_index, (descriptor_index, _, address, _) in enumerate(groups):
			image_data = decrypted_groups[descriptor_index]
			checksum_end = address + len(image_data)
			if (
				group_index < len(groups) - 1
				and len(image_data) >= 8
				and image_data[:4] == image_data[-4:]
			):
				checksum_end -= 4

			if group_index == len(groups) - 1:
				checksum_end = map_end + 1
			if not map_start <= checksum_end <= map_end + 1:
				raise ValueError(
					'Code group {} checksum range exceeds its RAMDLD flash map'
					.format(descriptor_index - 1)
				)

			checksum_ranges[descriptor_index] = (map_start, checksum_end)
			map_start = checksum_end

	checksums = {}
	for descriptor_index, (start, end) in checksum_ranges.items():
		start_offset = start - flash_base
		end_offset = end - flash_base
		checksum_image = bytearray(flash_image[start_offset:end_offset])
		code_group_index = descriptor_index - 1
		if code_group_index == 0:
			checksum_image[:8] = b'\xFF' * 8
		checksums[descriptor_index] = sum(checksum_image) & 0xFFFF

	missing = [
		descriptor_index for descriptor_index, _, _, _ in code_chunks
		if descriptor_index not in checksums
	]
	if missing:
		raise ValueError(
			'RAMDLD flash map did not produce checksums for code groups {}'
			.format(', '.join(str(index - 1) for index in missing))
		)
	return checksums


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


def _srecord(record_type, address, data=b'', address_size=4):
	if not 0 <= address < 1 << (address_size * 8):
		raise ValueError('S-record address is outside its address field')

	address_bytes = address.to_bytes(address_size, byteorder='big')
	count = len(address_bytes) + len(data) + 1
	if count > 0xFF:
		raise ValueError('S-record data is too large')
	checksum = (~(count + sum(address_bytes) + sum(data))) & 0xFF
	return (
		f'S{record_type}{count:02X}'.encode('ascii')
		+ address_bytes.hex().upper().encode('ascii')
		+ data.hex().upper().encode('ascii')
		+ f'{checksum:02X}'.encode('ascii')
	)


def _write_header_string(header, offset, value):
	header[offset:offset + len(value)] = value


def build_shx(out):
	if len(out) < HEADER_SIZE:
		raise ValueError('VFL header is shorter than the 100-byte header')

	phone_code = out[0x1D]
	branch_code = out[0x61]
	metadata = SHX_BRANCH_METADATA.get(branch_code)
	if metadata is None:
		raise ValueError('Unknown branch flag 0x{:02X} at 0061'.format(branch_code))
	phone_metadata = SHX_PHONE_METADATA.get((branch_code, phone_code), {})
	cg_header_tail = phone_metadata.get(
		'cg_header_tail', metadata['cg_header_tail']
	)

	descriptors = parse_vfl_decrypted_header(out)
	payload_offset = 150 if phone_code == 0x06 else HEADER_SIZE
	chunks = []
	payload_cursor = payload_offset
	for descriptor_index, (size, address) in enumerate(descriptors):
		if not size:
			continue
		end_address = address + size
		if not 0 <= address < end_address <= 0x100000000:
			raise ValueError('Code-group range is outside the SHX address space')
		chunk = out[payload_cursor:payload_cursor + size]
		if len(chunk) != size:
			raise ValueError('VFL code group extends beyond the decrypted payload')
		payload_cursor += size
		chunks.append((descriptor_index, size, address, chunk))

	if payload_cursor != len(out):
		raise ValueError(
			'VFL code group sizes total {} bytes, but the payload contains {} bytes'
			.format(payload_cursor - payload_offset, len(out) - payload_offset)
		)
	if not chunks:
		raise ValueError('VFL image contains no non-empty code groups')

	flash_base = 0x10000000 if branch_code == 0xFF else 0
	ramdld_chunks = [chunk for chunk in chunks if chunk[0] == 0]
	code_chunks = [chunk for chunk in chunks if chunk[0] > 0]
	if code_chunks and not ramdld_chunks:
		raise ValueError('VFL image has code groups but no RAMDLD flash map')
	group_checksums = (
		_checksum_code_groups_from_ramdld(
			ramdld_chunks[0][3], code_chunks, flash_base
		)
		if code_chunks
		else {}
	)

	header = bytearray(SHX_HEADER_SIZE)
	_write_header_string(header, 0x000, b'P2K Superfile')
	_write_header_string(
		header, 0x100, phone_metadata.get('version', metadata['version'])
	)
	_write_header_string(header, 0x120, b'2.00')
	_write_header_string(header, 0x140, b'Thu January 01 00:00:00 1970')
	_write_header_string(header, 0x1C0, b'UNIX Generated Superfile')
	_write_header_string(header, 0x310, b'2.20')

	# 0x3B0 counts RAMDLD and every non-empty VFL code-group descriptor.
	header[0x3B0] = len(chunks)
	header[0x3B6:0x3BC] = metadata['ramdld']
	group_tables = phone_metadata.get('group_tables', {})
	group_table = group_tables.get(out[0x1E], metadata['group_table'])
	if branch_code == 0xFF and out[0x1E] not in group_tables:
		file_code = out[0x1E]
		group_table += {
			0x01: bytes.fromhex('26 0B'),
			0x04: bytes.fromhex('80 16'),
		}.get(file_code, bytes.fromhex('00 00'))
	header[0x3C5:0x3C5 + len(group_table)] = group_table
	header[0x46B:0x471] = metadata['platform']
	header[0x472:0x474] = metadata['ma_group_info']

	for descriptor_index, size, address, chunk in code_chunks:
		code_group_index = descriptor_index - 1
		entry_offset = SHX_CG_HEADER_OFFSET + code_group_index * SHX_CG_HEADER_STRIDE
		if entry_offset + SHX_CG_HEADER_STRIDE > 0x480:
			raise ValueError('VFL contains more code groups than the SHX header supports')

		entry = bytearray(SHX_CG_HEADER_STRIDE)
		entry[:4] = address.to_bytes(4, byteorder='little')
		entry[4:8] = (address + size - 1).to_bytes(4, byteorder='little')
		entry_point = (
			address + 0x10
			if code_group_index == 4
			else metadata['cg_entry_point']
		)
		entry[8:12] = entry_point.to_bytes(4, byteorder='big')
		entry[12:16] = metadata['cg_header_middle']
		entry[16:24] = (
			bytes((0 if code_group_index == 0 else 1,))
			+ cg_header_tail
		)
		extra_info_mask = 0x0002 if code_group_index == 0 else 0
		entry[24:26] = group_checksums[descriptor_index].to_bytes(
			2, byteorder='little'
		)
		entry[26:28] = extra_info_mask.to_bytes(2, byteorder='little')
		header[entry_offset:entry_offset + SHX_CG_HEADER_STRIDE] = entry

	code_groups = []
	current_group = []
	for chunk in code_chunks:
		if current_group:
			_, previous_size, previous_address, _ = current_group[-1]
			if chunk[2] != previous_address + previous_size:
				code_groups.append(current_group)
				current_group = []
		current_group.append(chunk)
	if current_group:
		code_groups.append(current_group)

	srecord_groups = []
	if ramdld_chunks:
		_, size, address, data = ramdld_chunks[0]
		records = [
			_srecord('3', address + offset, data[offset:offset + SREC_DATA_SIZE])
			for offset in range(0, size, SREC_DATA_SIZE)
		]
		srecord_groups.append((records, address + metadata['ramdld_entry_adjustment']))

	for code_group in code_groups:
		start_address = code_group[0][2]
		end_address = max(address + size for _, size, address, _ in code_group)
		record_start = start_address & ~(SREC_DATA_SIZE - 1)
		record_end = (end_address + SREC_DATA_SIZE - 1) & ~(SREC_DATA_SIZE - 1)
		packed = bytearray(
			(SREC_FILL_PATTERN * ((record_end - record_start + len(SREC_FILL_PATTERN) - 1)
				// len(SREC_FILL_PATTERN)))[:record_end - record_start]
		)

		for _, size, address, data in code_group:
			overlay_start = max(record_start, address)
			overlay_end = min(record_end, address + size)
			if overlay_start < overlay_end:
				packed[overlay_start - record_start:overlay_end - record_start] = (
					data[overlay_start - address:overlay_end - address]
				)

		records = [
			_srecord(
				'3', record_start + offset,
				packed[offset:offset + SREC_DATA_SIZE]
			)
			for offset in range(0, len(packed), SREC_DATA_SIZE)
		]
		first_descriptor_index = code_group[0][0] - 1
		entry_point = (
			code_group[0][2] + 0x10
			if first_descriptor_index == 4
			else metadata['cg_entry_point']
		)
		srecord_groups.append((records, entry_point))

	header_record = _srecord('0', 0, b'HDR', address_size=2)
	header[0x1FEC:0x1FFE] = header_record + b'\r\n'
	first_record = srecord_groups[0][0][0]
	header[0x1FFE:0x2000] = first_record[:2]
	output = bytearray(header)
	last_group_index = len(srecord_groups) - 1
	for group_index, (records, entry_point) in enumerate(srecord_groups):
		if group_index == 0:
			output.extend(first_record[2:] + b'\r\n')
			remaining_records = records[1:]
		else:
			output.extend(header_record + b'\r\n')
			remaining_records = records

		for record in remaining_records:
			output.extend(record + b'\r\n')

		if group_index == last_group_index:
			# The final S7 address stores "CS" followed by the bytewise
			# checksum of the file preceding this terminator record.
			terminator_address = SHX_CHECKSUM_PREFIX | (sum(output) & 0xFFFF)
		else:
			terminator_address = entry_point
		output.extend(_srecord('7', terminator_address))
		if group_index < last_group_index:
			output.extend(b'\r\n')

	return bytes(output)


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
			shx = build_shx(out)
			dst.parent.mkdir(parents=True, exist_ok=True)
			dst.write_bytes(shx)
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

#!/usr/bin/python3
# Routines for packing and unpacking bits and bytes
import os
import re
import math
from hashlib import sha512
from readchar import readkey

from shared import BYTEORDER, TERM_WIDTH
from sd.common import sround, error, chunk_up
from sd.columns import auto_cols

#Dictionary list (for compression)
#Warning: list order must be mantainted for backwards compatability (max 128 items)
CRYPTO_LIST = "aes blowfish twofish serpent des rc4 rsa cbc cfb ctr gcm ecb ocb ofb ccm xts md4 md5 crc32 sha1 sha256 sha384 sha512 plain plain64 plain64be essiv bennbi null lmk tcw random".split()		# pylint: disable=C0301


#Type for data being stored for format byte. (max 8 items)
FORMAT_TYPE = ('text', 'file', 'dm', 'tc', 'vc')


def slicer(data, *args):
	"Slice up data into lists of lengths set by args."
	output = []
	start = 0
	stop = 0
	for arg in args:
		stop = stop + arg
		output.append(data[start:stop])
		start = stop
	if stop != len(data):
		print("Warning not all data used!", stop, 'used vs', len(data), 'total')
	return output


def pack_bytes(i):
	'''Take a positive integer and pack it into bytes with the format:
	<number of bytes><integer in big encoding>'''
	b = to_bytes(i)
	count = len(b)
	return to_bytes(count) + b


def unpack_bytes(data):
	count = int.from_bytes(data[:1], BYTEORDER)
	return str(int.from_bytes(data[1:][:count], BYTEORDER)), 1 + count


def bit_packer(*args):
	'''Pack unlimited amount of integers into bits
	Format: args = <bits>, <number>, <bits>, <number>, ...
	Warning: No negative numbers.
	'''
	numbers = list(args[1::2])
	bits = list(args[::2])
	output = ''
	for num in numbers:
		b = ('0' * 8 + bin(num)[2:])[-(bits.pop(0)):]
		if int(b, 2) != num:
			error("Not enough bits allocated for", num)
		else:
			output += b
	output = int(output, 2)
	return to_bytes(output)


def bit_unpacker(data, *bits):
	"Get numbers of <bits> length from packed binary data."
	if type(data) == bytes:
		data = bin(int.from_bytes(data, BYTEORDER))[2:]
	else:
		data = bin(data)[2:]
	if len(data) % 8:
		data = '0' * (8 - len(data) % 8) + data
	data = slicer(data, *bits)
	for x, _val in enumerate(data):
		data[x] = int(data[x], 2)
	return data


def pack_hex(num):
	'''Convert hex into bytes with the format:
	(assumes hex is 512 or less chars)
	<number of bytes><hex in bytes format>'''
	if len(num) > 512:
		error("Can not pack keys longer than 256 bit")
	count = math.ceil(len(num) / 2)
	# print('pack', count, num)
	return (count - 1).to_bytes(1, BYTEORDER) + bytes.fromhex(num)


def unpack_hex(data):
	"Convert key to hex"
	count = int.from_bytes(data[:1], BYTEORDER) + 1
	# print('unpack', count, data[1:][:count].hex())
	return data[1:][:count].hex(), count + 1


def show_bytes(num, length=64):
	"Convert a bytes or integer into a printable format"
	if type(num) in (bytes, bytearray):
		h = num.hex()
		if len(h) <= length:
			return str(len(num)) + ': ' + h
		else:
			length -= 4
			return str(len(num)) + ': ' + h[:length // 2] + '....' + h[-length // 2:]
	elif type(num) == int:
		return show_bytes(to_bytes(num), length)
	else:
		error("Show_bytes for", type(num), "not implemented")
		return None

def to_bytes(integer, count=0, endian=BYTEORDER):
	"Convert a positive integer into the needed number of bytes"
	if not count:
		count = 1 if integer < 256 else math.ceil(math.log(integer + 1, 256))
	return integer.to_bytes(count, endian)


def from_bytes(src, edian=BYTEORDER):
	"Convert bytes to int"
	return int.from_bytes(src, edian)


def dual_int_packer(aaa, bbb):
	'''Pack two integers into bytes with the format:
	<4bit length of int aaa length><4bit length of int bbb length><int 1><int 2>
	Cannot pack negative numbers
	'''
	if aaa < 0 or bbb < 0:
		error("Cannot pack negative numbers!")

	count = []
	chunks = []
	for i in (aaa, bbb):
		if i > 0:
			count.append(int(math.log(i + 1, 256) + 1))
			chunks.append(i.to_bytes(count[-1], BYTEORDER))
		else:
			count.append(0)
	count = count[0] * 16 + count[1]
	return count.to_bytes(1, BYTEORDER) + b''.join(chunks)



def dual_int_unpacker(data):
	'''
	Unpack ints and return int a, int b, and a pointer to how man bytes were used
	'''
	output = []

	count = int.from_bytes(data[0:1], BYTEORDER)
	a = count // 16
	b = count % 16
	count = a, b
	# print('unpack:', a,b)

	ptr = 1
	for x in range(2):
		if count[x] == 0:
			output.append(0)
			continue
		output.append(int.from_bytes(data[ptr:ptr + count[x]], BYTEORDER))
		ptr += count[x]
	return output + [ptr]


def var_packer(*args, endian=BYTEORDER):
	"pack variables into bytes with format: var, byte count, var, byte count..."
	output = b''
	for x in range(0, len(args), 2):
		var = args[x]
		count = args[x + 1]
		if type(var) == str:
			if len(var) != count:
				error(var, 'expected to be exactly', count, 'bytes long')
			output += var.encode()
		elif type(var) == bytes:
			output += var
		elif type(var) == int:
			output += var.to_bytes(count, endian)
		else:
			error("Packing the type:", type(var), "not yet implemented")
	return output


def var_unpacker(data, *args, endian=BYTEORDER):
	output = []
	ptr = 0
	for x in range(0, len(args), 2):
		t = args[x]  # type
		count = args[x + 1]
		var = data[ptr:ptr + count]
		ptr += count
		if t == 'str':
			output.append(var.decode('utf-8', errors='replace'))
		elif t == 'bytes':
			output.append(var)
		elif t == 'int':
			output.append(int.from_bytes(var, endian))
		else:
			error("Unpacking the type:", t, "not yet implemented")
	return output


def pack_ciphermode(mode):
	'''Format: ascii chars read as normal or
	non ascii byte means a dictionary lookup for that number value
	nul byte ends the stream
	Example: pack_ciphermode('aes-cbc-essiv:sha256') = 0x7f2d862d993a9300
	20 to 8 bytes'''
	if len(CRYPTO_LIST) > 128:
		error("Length of CRYPTO_LIST can not exceed 128")

	output = b''
	for word in re.split('\\W', mode):
		if word in CRYPTO_LIST:
			index = CRYPTO_LIST.index(word) + 127
			output += index.to_bytes(1, BYTEORDER)
		else:
			print("Symbol:", repr(word), "not found, switching to ascii encoding")
			for c in word.encode():
				if c >= 127:
					error("Can't encode character:", c)
			output += word.encode()
		mode = mode[len(word):]
		if mode:
			output += mode[0].encode()
			mode = mode[1:]
	return output + b'\x00'


def unpack_ciphermode(data):
	output = ''
	count = 0
	for c in data:
		count += 1
		if c == 0:
			break
		elif c >= 127:
			# Look up in dictionary
			output += CRYPTO_LIST[c - 127]
		else:
			output += chr(c)
	return output, count



def make_format_byte(devname=None, fmt='dm'):
	'''
	Pack the crypto type and partition number into a special byte.
	0 = Whole disk (specify offset within)
	'''
	part_bits = 5		# Max 2**5 - 1 = 31
	format_bits = 3		# Max 2**3 - 1 = 7

	if devname:
		part_num = re.findall('[0-9]*$', devname)[0]
		if part_num == '0':
			error("Partition numbers should start at 1")
		if part_num == '':
			part_num = 0
		part_num = int(part_num)
		if part_num > 2**part_bits - 1:
			error("You have exceeded the maximum number of partitions. ",
				  "Try storing data in one of the first", 2**part_bits - 1, 'partitions.')
	else:
		part_num = 0

	fmt = FORMAT_TYPE.index(fmt)

	return bit_packer(format_bits, fmt, part_bits, part_num)


def get_format_byte(byte):
	"Unpack the last byte (format byte) and return data, crypto_type, partition number"
	crypt, part_num = bit_unpacker(byte, 3, 5)	   # pylint: disable=unbalanced-tuple-unpacking
	return FORMAT_TYPE[crypt], part_num


def copy_bytearray(src, target, start=0, stop=0, tstart=0):
	'''Copy bytes into bytearray
	start is the start in the src
	stop is the end byte in the src (0 = unlimited)
	tstart is the start byte in the target
	'''

	stop = len(src) if not stop else stop
	if stop - start + tstart > len(target):
		stop = len(target) - tstart + start

	# print(start, stop, tstart)
	assert stop >= start
	assert stop <= len(src)



	for x in range(start, stop):
		target[x-start+tstart] = src[x]
	else:
		return start + 1
	return start + x + 1 			# Return a ptr to the next free byte


def wipe_bytes(arr, passes=3):
	"Erase a bytearray"
	# print('wiping', type(arr), arr)
	if arr:
		for _pas in range(passes):
			copy_bytearray(os.urandom(len(arr)), arr)


def log(binary, base=256):
	'''Example: log(b'\xff\xff') = 2.0; log(b'\00') = 0
	Testing tool for visualization of large numbers or byte strings'''
	if type(binary) in (bytes, bytearray):
		val = int.from_bytes(bytes(binary), BYTEORDER)
	else:
		val = binary
	return sround(math.log(val + 1, base))


def pack_table(table):
	''' Compress dmsetup table into bytes and verify result can be succesfully unpacked before returning'''

	# Pack into bytes
	table = table.split()
	table.pop(6)
	if table[2].lower().strip() != 'crypt':
		error("Can't handle dmtables with form: ", table[2])
	if not all([48 <= ord(c) <= 102 for c in table[4]]):
		error("Non Hex values found in table. Is this a LUKS device?")

	output = bytearray(\
		dual_int_packer(*map(int, table[0:2])) +\
		pack_ciphermode(table[3]) +\
		pack_hex(table[4]) +\
		dual_int_packer(*map(int, table[5:7])))
	src_len = len(' '.join(map(str, table)))
	print('Compressed', src_len, 'bytes into', len(output), 'bytes + Checksum.')

	# Verify the compression can be reversed error free
	if ' '.join(table[:7]) != ' '.join(unpack_table(output)):
		print("\nPack unpack mismatch:", ' '.join(table), 'vs',
			  ' '.join(unpack_table(output)), sep='\n')
		error("processing data with pack_table")
	else:
		print("Data precheck passed")
	return output


def unpack_table(data):
	"Unpack a dmsetup table"
	funcs = [dual_int_unpacker, unpack_ciphermode, unpack_hex, dual_int_unpacker]
	table = []
	ptr = 0
	for x, _val in enumerate(funcs):
		ret = funcs[x](data[ptr:])
		ptr += ret[-1]
		table += list(ret[:-1])
	table.insert(2, 'crypt')
	return list(map(str, table))



class ByteTracker:
	'''
	Reserve parts of the hash while keeping track of who used what.
	Does not actually store the hash, only slice pointers
	'''

	def __init__(self, hash_len, num_slots=64):
		self.hash_len = hash_len        # Bytes available in the hash
		self.num_slots = num_slots      # How many slots of data to reserve per request
		self.ptr = 0                    # Pointer to the first unreserved byte

	def reserve(self, count, slots=None):
		"Reserve sections of the hash for a number of slots"
		ptr = self.ptr
		sections = []
		if not slots:
			slots = self.num_slots
		for _x in range(slots):
			sections.append(slice(ptr, ptr + count))
			ptr += count
		# print("Reserved:", slots, "slots", "from byte", self.ptr, "to", ptr)
		self.ptr = ptr
		if self.ptr + 1 >= self.hash_len:
			raise ValueError("Requested more bytes than available in hash!", ptr, '>', self.hash_len)
		return sections


class ABA:
	'''
	Advanced Byte Arrays with checksums and more
	Format: <8 byte checksum> <1 byte length> <data>
	'''

	chk_len = 8
	# Number of Checksum bytes, Default is 64 bits because shamir will see thousands of
	# false matches before selecting the correct one.
	# 32 bit (4 bytes) would provide maybe 1 in a million chance of selecting the wrong slot,
		# but would make much more sense in normal mode.
	# 64 bit (8 bytes) provides better than 1 in quadrillion chance
		# (less than the odds of an asteroid falling on your house)
	# 48 bit (6 bytes) would be a reasonable compromise at 1 in billions, but would only save 2 bytes.


	header = chk_len + 1			# Total length of the header
	start = header					# Start of the data
	end = start						# End of the data

	def __init__(self, src=b'', size=64, seed=b'', raw=False):
		self.seed = seed				# Hash of bytes
		self.datas = []					# data bytearrays produced for copying
		self.updated = True				# Will self.data() return different data?
		if src:
			if raw:
				self.arr = bytearray(src)
			else:
				if len(src) + self.header > size:
					size = chunk_up(len(src) + self.header, size)
				if size - self.header > 255:
					raise ValueError(size, "Lengths over 255 not supported yet")
				self.arr = bytearray(size)		# The mutable Bytearray
				self.read(src)
		# print('New ABA', size, self.start, self.end)


	def __repr__(self):
		#return bytes(self.data()).decode('utf-8', errors='replace')
		return self.__str__()

	def __str__(self):
		out = ["ABA",
		       self.__len__(),
		       len(self.arr),
		       self.validate(),
		       repr(self.arr)]
		return ' | '.join(map(str, out))

	def __eq__(self, other):
		return self.data() == other

	def __len__(self):
		"Length of actual data portion"
		return self.end - self.start

	def __bytes__(self):
		return bytes(self.data())

	def hex(self):
		return self.data().hex()

	def data(self, checksum=False):
		"Return bytearray of actual data that can be destroyed later"
		if not self.updated:
			return self.datas[-1]

		start = 0 if checksum else self.header
		end = self.end
		target = bytearray(end - start)
		copy_bytearray(self.arr, target, start=start, stop=end)
		self.datas.append(target)
		self.updated = False
		if len(self.datas) >= 3:
			wipe_bytes(self.datas[0])
			self.datas.pop(0)
		return target


	def read(self, src):
		"Read bytes into array"
		#todo expand to fit
		if type(src) not in (bytes, bytearray):
			src = src.encode()
		copy_bytearray(src, self.arr, tstart=self.end)
		self.end += len(src)
		self.prepend()
		self.updated = True


	def checksum(self):
		"Calculate the correct checksum and truncate it"
		# Md5 or CRC32 would be fine here, but Sha512 seems to be fast enough
		if self.seed:
			h = sha512(self.seed)
			h.update(self.data())
		else:
			h = sha512(self.data())
		return h.digest()[:self.chk_len]

	def prepend(self):
		"Append a checksum to the front of the data"
		if self.__len__() > 255:
			error("Max supported data length is 255")
		lb = to_bytes(self.__len__())
		copy_bytearray(self.checksum() + lb, self.arr)

	def read_lb(self):
		"Read length byte"
		return self.arr[self.chk_len]


	def validate(self):
		'''
		Test if self.arr already has correct checksum and update based on length byte
		Also update self.end based on length byte
		'''
		#Read Length byte, make sure it's within bounds, if not return False
		lb = self.read_lb()
		end = self.header + lb
		if end > len(self.arr):
			return False

		#Temporarily set self.end for self.checksum, then revert if incorrect checksum
		old = self.end
		self.end = end
		status = bool(self.checksum() == self.arr[:self.chk_len])
		if not status:
			self.end = old
		return status

	def scramble(self, src=None):
		"Fill remainder of bytearray with junk"
		size = len(self.arr) - self.end
		if not src:
			src = os.urandom(size)
		copy_bytearray(src, self.arr, tstart=self.end)

	def destroy(self):
		"Wipe the bytes before deleting"
		for array in self.datas:
			wipe_bytes(array)
		del self.datas
		wipe_bytes(self.arr)
		del self.arr


	def show(self, prompt=''):
		"Show text and then erase it."
		print('\nData is presented below, press Enter to continue:')
		print(prompt, end='', flush=True)
		for x in range(self.start, self.end):
			print(chr(self.arr[x]), end='')
		print(end='', flush=True)
		readkey()
		print('\r' * TERM_WIDTH + ' ' * TERM_WIDTH)


class FileMapper:
	'''
	Map sections of disk or file and combine them
	to make an abstract file that behaves like a standard one.
	Example: Combine the sections of the src file below to make an abstract file:
	__________XXXXX_____XXXXX_____________________________
	The ___ bytes are untouched while The XXXX bytes are combined to make the abstract file.

	In this example maps=(10, 15), (20, 25)
	meaning 5 bytes starting at 10 and 5 bytes starting at 20
	for a total self.size of 10

	'''

	def __init__(self, name, *maps, mode='r+b', verbose=False):
		self.src = open(name, mode=mode)
		self.mapper = []			 	# Length of seach mapped segment
		self.starts = []			  	# Starting positions in the src file
		self.section = 0				# Which mapped section to use
		self.mapper_ptr = 0				# Where in the mapped section
		self.pos = 0					# Current position in the abstract file
		self.verbose = verbose
		self.mode = mode

		for start, end in maps:
			assert end > start
			self.mapper.append(end - start)
			self.starts.append(start)

		self.size = sum(self.mapper)	# Total abstract file size
		self.max_section = len(self.mapper) - 1
		self.update_seek()

	def __repr__(self):
		out = [('section =', self.section),
			   ('ptr = ', self.mapper_ptr),
			   ('pos =', self.pos),
			   ('src tell', self.src.tell()),
			   ]
		out = auto_cols(out, printme=False)
		return '\n'.join([' '.join(line) for line in out])


	def _rw(self, request, mode='read', data=None):
		'''
		Read or write to the file
		request = bytes requested to be read or written
		mode = read, write or seek
		data = data to write in write mode
		'''
		if self.pos >= self.size:
			if mode == 'read':
				return b''
			else:
				return None

		# Bytes available in the section
		avail = self.mapper[self.section] - self.mapper_ptr

		# Determine bytes available in section
		if avail >= request:
			count = request
		else:
			count = avail

		if self.verbose:
			print('\navailable =', avail)
			print('request =', request)
			print('count =', count)


		# Read or write count bytes from the current section
		# print(self.src.tell(), end=' ')
		if mode == 'read':
			data = self.src.read(count)
		elif mode == 'write':
			self.src.write(data[:count])
		elif mode == 'seek':
			self.src.seek(count, 1)
		# print('->', self.src.tell())

		# Adjust the pointers
		avail -= count
		self.pos += count
		if avail == 0 and self.section < self.max_section:
			# If reached a new section reset the pointers
			self.section += 1
			self.mapper_ptr = 0
			self.update_seek()
		else:
			self.mapper_ptr += count

		# Return the data if applicable
		if request > count:
			if mode == 'read':
				return data + self._rw(request - count, mode)
			elif mode == 'write':
				return self._rw(request - count, mode, data[count:])
			elif mode == 'seek':
				return self._rw(request - count, mode)

		else:
			if mode == 'read':
				return data
			else:
				return None

	def read(self, count):
		return self._rw(count)

	def write(self, data):
		self._rw(len(data), mode='write', data=data)
		self.src.flush()

	def update_seek(self):
		"Update the src tell to start of section"
		self.src.seek(self.starts[self.section], 0)

	def seek(self, count, ref=None):
		# -count defaults to end of file
		if count < 0 and ref == None:
			ref = 2
		if ref == None:
			ref = 0
		# print('seeking', count, ref)

		# Beginning of file
		if ref == 0:
			if count < 0:
				count = 0
			self.section = 0
			self.pos = 0
			self.mapper_ptr = 0
			self.update_seek()
			ref = 1

		# Relative seek
		if ref == 1:
			if count < 0:
				if self.mapper_ptr > -count:
					self.pos += count
					self.mapper_ptr += count
					self.src.seek(count, 1)
				else:
					return self.seek(self.pos + count, 0)
			else:
				self._rw(count, mode='seek')

		# End of file
		if ref == 2:
			return self.seek(self.size+count, 0)


	def tell(self):
		return self.pos

	def flush(self):
		return self.src.flush()

	def close(self):
		return self.src.close()


# self = FileMapper('/tmp/test', (10, 20), (30, 40), verbose=True)

package crypto

// ChaCha20 algorithm and test vector from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04

func ChaChaInit(chachaGrid *[16]uint32, key *[32]byte, nonce *[8]byte) {
	var i, j uint

	// ChaCha20 uses a 4 x 4 grid of uint32:
	//
	//   +------------+------------+------------+------------+
	//   | const    0 | constant 1 | constant 2 | constant 3 |
	//   | 0x61707865 | 0x3320646e | 0x79622d32 | 0x6b206574 |
	//   +------------+------------+------------+------------+
	//   | key      4 | key      5 | key      6 | key      7 |
	//   +------------+------------+------------+------------+
	//   | key      8 | key      9 | key     10 | key     11 |
	//   +------------+------------+------------+------------+
	//   | block   12 | block   13 | nonce   14 | nonce   15 |
	//   +------------+------------+------------+------------+
	//
	// The first four input words are constants: (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574).
	//
	// Input words 4 through 11 are taken from the 256-bit key by reading the bytes in little-endian order, in 4-byte chunks.
	//
	// Input words 12 and 13 are a block counter, with word 12 overflowing into word 13. The block counter words are initially zero.
	//
	// Lastly, words 14 and 15 are taken from an 8-byte nonce, again by reading the bytes in little-endian order, in 4-byte chunks.

	// constants
	chachaGrid[0] = 0x61707865
	chachaGrid[1] = 0x3320646e
	chachaGrid[2] = 0x79622d32
	chachaGrid[3] = 0x6b206574

	// 256 bits key as 8 Little Endian uint32
	for j = 0; j < 8; j++ {
		chachaGrid[j+4] = 0
		for i = 0; i < 4; i++ {
			chachaGrid[j+4] += uint32(key[j*4+i]) << (8 * i)
		}
	}

	// block counter
	chachaGrid[12] = 0
	chachaGrid[13] = 0

	// nonce as 2 consecutives Little Endian uint32
	for j = 0; j < 2; j++ {
		chachaGrid[j+14] = 0
		for i = 0; i < 4; i++ {
			chachaGrid[j+14] += uint32(nonce[j*4+i]) << (8 * i)
		}
	}
}

func ChaCha20(keystream *[64]byte, chachaGrid *[16]uint32) {
	var x [16]uint32
	var a, b, c, d uint32

	// chacha use a 4 x 4 grid of uint32:
	//
	//   +-----+-----+-----+-----+
	//   | x0  | x1  | x2  | x3  |
	//   +-----+-----+-----+-----+
	//   | x4  | x5  | x6  | x7  |
	//   +-----+-----+-----+-----+
	//   | x8  | x9  | x10 | x11 |
	//   +-----+-----+-----+-----+
	//   | x12 | x13 | x14 | x15 |
	//   +-----+-----+-----+-----+
	for i := 0; i < 16; i++ {
		x[i] = chachaGrid[i]
	}

	// ChaCha20 consists of 20 rounds, alternating between "column" rounds and "diagonal" rounds.
	// Each round applies the "quarterround" function four times, to a different set of words each time.
	for i := 0; i < 10; i++ {

		// QUARTER-ROUND on column 1:
		//
		//   +-----+-----+-----+-----+
		//   | x0  |     |     |     |
		//   +-----+-----+-----+-----+
		//   | x4  |     |     |     |
		//   +-----+-----+-----+-----+
		//   | x8  |     |     |     |
		//   +-----+-----+-----+-----+
		//   | x12 |     |     |     |
		//   +-----+-----+-----+-----+
		//
		// x[0], x[4], x[8], x[12] = quarterround(x[0], x[4], x[8], x[12])
		a = x[0]
		b = x[4]
		c = x[8]
		d = x[12]
		a += b
		d ^= a
		d = d<<16 | d>>16 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<12 | b>>20 // this is a bitwise left rotation
		a += b
		d ^= a
		d = d<<8 | d>>24 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<7 | b>>25 // this is a bitwise left rotation
		x[0] = a
		x[4] = b
		x[8] = c
		x[12] = d

		// QUARTER-ROUND on column 2:
		//
		//   +-----+-----+-----+-----+
		//   |     | x1  |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x5  |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x9  |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x13 |     |     |
		//   +-----+-----+-----+-----+
		//
		// x[1], x[5], x[9], x[13] = quarterround(x[1], x[5], x[9], x[13])
		a = x[1]
		b = x[5]
		c = x[9]
		d = x[13]
		a += b
		d ^= a
		d = d<<16 | d>>16 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<12 | b>>20 // this is a bitwise left rotation
		a += b
		d ^= a
		d = d<<8 | d>>24 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<7 | b>>25 // this is a bitwise left rotation
		x[1] = a
		x[5] = b
		x[9] = c
		x[13] = d

		// QUARTER-ROUND on column 3:
		//
		//   +-----+-----+-----+-----+
		//   |     |     | x2  |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x6  |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x10 |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x14 |     |
		//   +-----+-----+-----+-----+
		//
		// x[2], x[6], x[10], x[14] = quarterround(x[2], x[6], x[10], x[14])
		a = x[2]
		b = x[6]
		c = x[10]
		d = x[14]
		a += b
		d ^= a
		d = d<<16 | d>>16 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<12 | b>>20 // this is a bitwise left rotation
		a += b
		d ^= a
		d = d<<8 | d>>24 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<7 | b>>25 // this is a bitwise left rotation
		x[2] = a
		x[6] = b
		x[10] = c
		x[14] = d

		// QUARTER-ROUND on column 4:
		//
		//   +-----+-----+-----+-----+
		//   |     |     |     | x3  |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x7  |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x11 |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x15 |
		//   +-----+-----+-----+-----+
		//
		// x[3], x[7], x[11], x[15] = quarterround(x[3], x[7], x[11], x[15])
		a = x[3]
		b = x[7]
		c = x[11]
		d = x[15]
		a += b
		d ^= a
		d = d<<16 | d>>16 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<12 | b>>20 // this is a bitwise left rotation
		a += b
		d ^= a
		d = d<<8 | d>>24 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<7 | b>>25 // this is a bitwise left rotation
		x[3] = a
		x[7] = b
		x[11] = c
		x[15] = d

		// QUARTER-ROUND on diagonal 1:
		//
		//   +-----+-----+-----+-----+
		//   | x0  |     |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x5  |     |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x10 |     |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x15 |
		//   +-----+-----+-----+-----+
		//
		// x[0], x[5], x[10], x[15] = quarterround(x[0], x[5], x[10], x[15])
		a = x[0]
		b = x[5]
		c = x[10]
		d = x[15]
		a += b
		d ^= a
		d = d<<16 | d>>16 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<12 | b>>20 // this is a bitwise left rotation
		a += b
		d ^= a
		d = d<<8 | d>>24 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<7 | b>>25 // this is a bitwise left rotation
		x[0] = a
		x[5] = b
		x[10] = c
		x[15] = d

		// QUARTER-ROUND on diagonal 2:
		//
		//   +-----+-----+-----+-----+
		//   |     | x1  |     |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x6  |     |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x11 |
		//   +-----+-----+-----+-----+
		//   | x12 |     |     |     |
		//   +-----+-----+-----+-----+
		//
		// x[1], x[6], x[11], x[12] = quarterround(x[1], x[6], x[11], x[12])
		a = x[1]
		b = x[6]
		c = x[11]
		d = x[12]
		a += b
		d ^= a
		d = d<<16 | d>>16 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<12 | b>>20 // this is a bitwise left rotation
		a += b
		d ^= a
		d = d<<8 | d>>24 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<7 | b>>25 // this is a bitwise left rotation
		x[1] = a
		x[6] = b
		x[11] = c
		x[12] = d

		// QUARTER-ROUND on diagonal 3:
		//
		//   +-----+-----+-----+-----+
		//   |     |     | x2  |     |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x7  |
		//   +-----+-----+-----+-----+
		//   | x8  |     |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x13 |     |     |
		//   +-----+-----+-----+-----+
		//
		// x[2], x[7], x[8], x[13] = quarterround(x[2], x[7], x[8], x[13])
		a = x[2]
		b = x[7]
		c = x[8]
		d = x[13]
		a += b
		d ^= a
		d = d<<16 | d>>16 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<12 | b>>20 // this is a bitwise left rotation
		a += b
		d ^= a
		d = d<<8 | d>>24 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<7 | b>>25 // this is a bitwise left rotation
		x[2] = a
		x[7] = b
		x[8] = c
		x[13] = d

		// QUARTER-ROUND on diagonal 4:
		//
		//   +-----+-----+-----+-----+
		//   |     |     |     | x3  |
		//   +-----+-----+-----+-----+
		//   | x4  |     |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x9  |     |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x14 |     |
		//   +-----+-----+-----+-----+
		//
		// x[3], x[4], x[9], x[14] = quarterround(x[3], x[4], x[9], x[14])
		a = x[3]
		b = x[4]
		c = x[9]
		d = x[14]
		a += b
		d ^= a
		d = d<<16 | d>>16 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<12 | b>>20 // this is a bitwise left rotation
		a += b
		d ^= a
		d = d<<8 | d>>24 // this is a bitwise left rotation
		c += d
		b ^= c
		b = b<<7 | b>>25 // this is a bitwise left rotation
		x[3] = a
		x[4] = b
		x[9] = c
		x[14] = d
	}

	// After 20 rounds of the above processing, the original 16 input words are added to the 16 words to form the 16 output words.
	for i := 0; i < 16; i++ {
		x[i] += chachaGrid[i]
	}

	// The 64 output bytes are generated from the 16 output words by serialising them in little-endian order and concatenating the results.
	for i := 0; i < 64; i += 4 {
		j := x[i>>2]
		keystream[i] = byte(j)
		keystream[i+1] = byte(j >> 8)
		keystream[i+2] = byte(j >> 16)
		keystream[i+3] = byte(j >> 24)
	}

	// Input words 12 and 13 are a block counter, with word 12 overflowing into word 13.
	chachaGrid[12]++
	if chachaGrid[12] == 0 {
		chachaGrid[13]++
	}
}

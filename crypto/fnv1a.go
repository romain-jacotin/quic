package crypto

func HashFNV1A_64(inputdata []byte) uint64 {
	var val uint64 = 14695981039346656037 // offset_basis = 14695981039346656037
	const FNV_64_PRIME = 1099511628211

	for _, v := range inputdata {
		// xor the bottom with the current octet
		val ^= uint64(v)

		// multiply by the 64 bit FNV magic prime mod 2^64
		// fnv_prime = 1099511628211
		val *= FNV_64_PRIME
	}
	return val
}

func HashFNV1A_128(inputdata []byte) (high, low uint64) {
	// offset_basis = 144066263297769815596495629667062367629
	// 				= 0x6C62272E 07BB0142 62B82175 6295C58D
	// Convert offset_basis into a base 2^32 array
	var val = [4]uint64{0x6295C58D, 0x62B82175, 0x07BB0142, 0x6C62272E}
	var tmp [4]uint64 // tmp 128 bit value

	const FNV_128_PRIME_LOW = 0x0000013B
	const FNV_128_PRIME_SHIFT = 24

	for _, v := range inputdata {
		// xor the bottom with the current octet
		val[0] ^= uint64(v)

		// multiply by the 128 bit FNV magic prime mod 2^128
		// fnv_prime	= 309485009821345068724781371 (decimal)
		// 				= 0x0000000001000000000000000000013B (hexadecimal)
		// 				= 0x00000000 	0x01000000 				0x00000000	0x0000013B (in 4*32 words)
		//				= 0x0			1<<FNV_128_PRIME_SHIFT	0x0			FNV_128_PRIME_LOW
		//
		// FNV_128_PRIME_LOW = 0x0000013B
		// FNV_128_PRIME_SHIFT = 24

		// multiply by the lowest order digit base 2^32 and by the other non-zero digit
		tmp[0] = val[0] * FNV_128_PRIME_LOW
		tmp[1] = val[1] * FNV_128_PRIME_LOW
		tmp[2] = val[2]*FNV_128_PRIME_LOW + val[0]<<FNV_128_PRIME_SHIFT
		tmp[3] = val[3]*FNV_128_PRIME_LOW + val[1]<<FNV_128_PRIME_SHIFT

		// propagate carries
		tmp[1] += (tmp[0] >> 32)
		tmp[2] += (tmp[1] >> 32)
		tmp[3] += (tmp[2] >> 32)

		val[0] = tmp[0] & 0xffffffff
		val[1] = tmp[1] & 0xffffffff
		val[2] = tmp[2] & 0xffffffff
		val[3] = tmp[3] // & 0xffffffff
		// Doing a val[3] &= 0xffffffff is not really needed since it simply
		// removes multiples of 2^128.  We can discard these excess bits
		// outside of the loop when writing the hash in Little Endian.
	}
	return val[3]<<32 | val[2], val[1]<<32 | val[0]
}

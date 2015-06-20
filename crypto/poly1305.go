package crypto

import "errors"

func mul_reg(dst *[4]uint64, a, b uint64) {
	a0 := a & 0xffffffff
	a1 := a >> 32
	b0 := b & 0xffffffff
	b1 := b >> 32
	dst0 := a0 * b0
	dst1 := dst0 >> 32
	dst[0] = dst0 & 0xffffffff
	dst1 += a1 * b0
	dst2 := dst1 >> 32
	dst1 &= 0xffffffff
	dst1 += a0 * b1
	dst2 += dst1 >> 32
	dst3 := dst2 >> 32
	dst2 &= 0xffffffff
	dst2 += a1 * b1
	dst3 += dst2 >> 32
	dst[1] = dst1 & 0xffffffff
	dst[2] = dst2 & 0xffffffff
	dst[3] = dst3 & 0xffffffff
}

func addlo_reg(dst *[4]uint64, a uint64) {
	dst0 := dst[0] + (a & 0xffffffff)
	dst1 := dst[1] + (a >> 32)
	dst1 += dst0 >> 32
	dst[0] = dst0 & 0xffffffff
	dst2 := dst[2] + (dst1 >> 32)
	dst[1] = dst1 & 0xffffffff
	dst3 := dst[3] + (dst2 >> 32)
	dst[2] = dst2 & 0xffffffff
	dst[3] = dst3 & 0xffffffff
}

func add_reg(dst, a *[4]uint64) {
	dst0 := dst[0] + a[0]
	dst1 := dst[1] + a[1]
	dst2 := dst[2] + a[2]
	dst3 := dst[3] + a[3]
	dst1 += dst0 >> 32
	dst[0] = dst0 & 0xffffffff
	dst2 = dst2 + (dst1 >> 32)
	dst[1] = dst1 & 0xffffffff
	dst3 += (dst2 >> 32)
	dst[2] = dst2 & 0xffffffff
	dst[3] = dst3 & 0xffffffff
}

func shr_reg(src *[4]uint64, bit uint) uint64 {
	return (src[1] >> (bit - 32)) + (src[2] << (64 - bit)) + (src[3] << (96 - bit))
}

func Poly1305(data, r_key, s_key []byte) (err error, high_mac, low_mac uint64) {
	var r0, r1, r2, h0, h1, h2, c, c0, c1, c2, s1, s2 uint64
	var i, j, l uint
	var d, d0, d1, d2 [4]uint64

	if (len(r_key) != 16) || (len(s_key) != 16) {
		return errors.New("Poly1305 : mac, r and s keys must have 16 bytes length"), 0, 0
	}

	l = uint(len(data))

	// Variables initialization: read 'r' and 's' as Little Endian unsigned int
	// r &= 0xffffffc0ffffffc0ffffffc0fffffff as required by the Poly1305 specifications
	//
	// NOTE: we need 'r', 'h' and 'c' to be uint130 because of the required modulus 2^130 - 5
	//       uint130(r) = 42 most significant bits(r2) + 44 middle bits(r1) + 44 less significant bits(r0)

	// r0 = LSB 44 bits of 'r' as uint130
	r0 = uint64(r_key[0]) |
		(uint64(r_key[1]) << 8) |
		(uint64(r_key[2]) << 16) |
		(uint64(r_key[3]) << 24) |
		(uint64(r_key[4]) << 32) |
		(uint64(r_key[5]) << 40)
	r0 &= 0xffc0fffffff

	// r1 = middle 44 bits of 'r' as uint130
	r1 = (uint64(r_key[5]) >> 4) |
		(uint64(r_key[6]) << 4) |
		(uint64(r_key[7]) << 12) |
		(uint64(r_key[8]) << 20) |
		(uint64(r_key[9]) << 28) |
		(uint64(r_key[10]) << 36)
	r1 &= 0xfffffc0ffff

	// r2 = MSB 42 bits of 'r' as uint130
	r2 = uint64(r_key[11]) |
		(uint64(r_key[12]) << 8) |
		(uint64(r_key[13]) << 16) |
		(uint64(r_key[14]) << 24) |
		(uint64(r_key[15]) << 32)
	r2 &= 0x00ffffffc0f

	s1 = (r1 * (5 << 2))
	s2 = (r2 * (5 << 2))

	// h = 0 --> zero is already the default value for h0, h1 and h2, so nothing to do :-)

	i = 0
	for i < l {
		// Read 'c' from a chunk of 16 bytes (or less if not enough data) as a Little Endian unsigned integer (uint130)
		// uint130(c) = 42 most significant bits(c2) + 44 middle bits(c1) + 44 less significant bits(c0)
		c0 = 0
		c1 = 0
		c2 = 0
		for j = 0; (j < 16) && (i < l); j++ {
			if j < 5 {
				c0 |= uint64(data[i]) << (j << 3)
			} else if j == 5 {
				c0 |= uint64(data[i]) << 40
				c1 |= uint64(data[i]) >> 4
			} else if j < 11 {
				c1 |= uint64(data[i]) << (4 + ((j - 6) << 3))
			} else { // j >= 11
				c2 |= uint64(data[i]) << ((j - 11) << 3)
			}
			i++
		}
		c0 &= 0xfffffffffff
		c1 &= 0xfffffffffff
		c2 &= 0x3ffffffffff

		// if chunk'size == 16 bytes then add a 17th byte = 0x01
		// if chunk'size  < 16 bytes then add a last byte = 0x01, and bytes up to 17th are equals to 0
		if j < 6 {
			c0 |= 1 << (j * 8)
		} else if j < 11 {
			c1 |= 1 << (4 + (j-6)*8)
		} else { // j >= 11
			c2 |= 1 << ((j - 11) * 8)
		}

		// for each chunk 'c', update 'h' like this:      h = ((h + c) * r) % ((2^130)-5)

		// Calculate h = h + c
		h0 += c0
		h1 += c1
		h2 += c2

		// Calculate h = h * r --> MUST DEBUG !!!!

		// d0 = h0*r0 + h1*(r2*(5<<2)) + h2*(r1*(5<<2))
		mul_reg(&d0, h0, r0)
		mul_reg(&d, h1, s2)
		add_reg(&d0, &d)
		mul_reg(&d, h2, s1)
		add_reg(&d0, &d)

		// d1 = h0*r1 + h1*r0 + h2*(r2*(5<<2))
		mul_reg(&d1, h0, r1)
		mul_reg(&d, h1, r0)
		add_reg(&d1, &d)
		mul_reg(&d, h2, s2)
		add_reg(&d1, &d)

		// d2 = h0*r2 + h1*r1 + h2*r0
		mul_reg(&d2, h0, r2)
		mul_reg(&d, h1, r1)
		add_reg(&d2, &d)
		mul_reg(&d, h2, r0)
		add_reg(&d2, &d)

		// partial h %= ((2^130)-5)
		// In fact we don't calculate the complete modulo value, but the lowest value that is < 2^130

		// Convert d (= uint128 simulated with 4 uint64 that contains 32+32+32+32 bits)
		// into h (= uint130 simulated with 3 uint64 that contains 42+44+44) and propagate the carry ( = c )

		// h0 = LSB 44 bits of d0
		c = (d0[1] >> 12) + (d0[2] << 20) + (d0[3] << 52)
		h0 = (d0[0] + (d0[1] << 32)) & 0xfffffffffff

		// h1 = LSB 44 bits of d1
		addlo_reg(&d1, c)
		c = (d1[1] >> 12) + (d1[2] << 20) + (d1[3] << 52)
		h1 = (d1[0] + (d1[1] << 32)) & 0xfffffffffff

		// h1 = LSB 42 bits of d2
		addlo_reg(&d2, c)
		c = (d2[1] >> 10) + (d2[2] << 22) + (d2[3] << 54)
		h2 = (d2[0] + (d2[1] << 32)) & 0x3ffffffffff

		// Use the carry (= c) to calculate the partial modulo (2^130 - 5)
		// partial modulo = multiply the 130 bits value by the carry (the carry is the upper bit at the left of the 130 bits)
		h0 += c * 5
		c = (h0 >> 44)
		h0 = h0 & 0xfffffffffff
		h1 += c
		// Note: the carry is not fully propagated into h here, the full carry will be made after the last chunk (=after the 'chunk' loop)
	}

	// Fully carry h
	c = (h1 >> 44)
	h1 &= 0xfffffffffff
	h2 += c
	c = (h2 >> 42)
	h2 &= 0x3ffffffffff
	h0 += c * 5
	c = (h0 >> 44)
	h0 &= 0xfffffffffff
	h1 += c
	c = (h1 >> 44)
	h1 &= 0xfffffffffff
	h2 += c
	c = (h2 >> 42)
	h2 &= 0x3ffffffffff
	h0 += c * 5
	c = (h0 >> 44)
	h0 &= 0xfffffffffff
	h1 += c

	// Now it is the final step to compute h % ((2^130)-5)
	// We compare 'h' and 'p' :
	//   if h < p then h is the final modulus value
	//   if h >= p then the final value is h - p
	// Compute h - p = h - (2^130 - 5) = h + 5 - 2^130 = h + 5 - (1 << 130)
	c0 = h0 + 5
	c = c0 >> 44
	c0 &= 0xfffffffffff
	c1 = h1 + c
	c = c1 >> 44
	c1 &= 0xfffffffffff
	c2 = h2 + c - (1 << 42)

	// select h if h < p, or (h - p) if h >= p
	c = (c2 >> 63) - 1
	c0 &= c
	c1 &= c
	c2 &= c
	c = ^c
	h0 = (h0 & c) | c0
	h1 = (h1 & c) | c1
	h2 = (h2 & c) | c2

	// Read 's' as Little Endian uint128 (c0 = low 64 bits, c1 = high 64 bits)
	c0 = 0
	c1 = 0
	for i = 0; i < 8; i++ {
		c0 |= uint64(s_key[i]) << (i << 3)
		c1 |= uint64(s_key[i+8]) << (i << 3)
	}

	// h = h + s (in uint130)
	h0 += ((c0) & 0xfffffffffff)
	c = h0 >> 44
	h0 &= 0xfffffffffff

	h1 += (((c0 >> 44) | (c1 << 20)) & 0xfffffffffff) + c
	c = h1 >> 44
	h1 &= 0xfffffffffff

	h2 += ((c1 >> 24) & 0x3ffffffffff) + c
	h2 &= 0x3ffffffffff

	// Transform h in uint128: h = h % (2^128)
	h0 = h0 + (h1 << 44)
	h1 = ((h1 >> 20) + (h2 << 24))

	return nil, h1, h0
}

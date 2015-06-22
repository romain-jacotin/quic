package crypto

import "errors"
import "encoding/binary"

type Poly1305 struct {
	r0, r1, r2                       uint64 // r_key coded in a uint130 (44-bit + 44-bit + 42-bit)
	s_key_begin, s_key_end           uint64 // s_key coded in two uint64
	s1_low, s1_high, s2_low, s2_high uint64 // precomputation for code optimization
}

func NewPoly1305(key []byte) (*Poly1305, error) {
	if len(key) < 32 {
		return nil, errors.New("NewPoly1305 : key must be at least 256-bit")
	}
	p := new(Poly1305)

	// Variables initialization: read 'r' and 's' as Little Endian unsigned int
	// r &= 0xffffffc0ffffffc0ffffffc0fffffff as required by the Poly1305 specifications
	//
	// NOTE: we need 'r', 'h' and 'c' to be uint130 because of the required modulus 2^130 - 5
	//       uint130(r) = 42 most significant bits(r2) + 44 middle bits(r1) + 44 less significant bits(r0)

	// r0 = LSB 44 bits of 'r' as uint130
	p.r0 = uint64(key[0]) |
		(uint64(key[1]) << 8) |
		(uint64(key[2]) << 16) |
		(uint64(key[3]) << 24) |
		(uint64(key[4]) << 32) |
		(uint64(key[5]) << 40)
	p.r0 &= 0xffc0fffffff

	// r1 = middle 44 bits of 'r' as uint130
	p.r1 = (uint64(key[5]) >> 4) |
		(uint64(key[6]) << 4) |
		(uint64(key[7]) << 12) |
		(uint64(key[8]) << 20) |
		(uint64(key[9]) << 28) |
		(uint64(key[10]) << 36)
	p.r1 &= 0xfffffc0ffff

	// r2 = MSB 42 bits of 'r' as uint130
	p.r2 = uint64(key[11]) |
		(uint64(key[12]) << 8) |
		(uint64(key[13]) << 16) |
		(uint64(key[14]) << 24) |
		(uint64(key[15]) << 32)
	p.r2 &= 0x00ffffffc0f

	// Read 's' as Little Endian uint128 (s_key_begin = low 64 bits, s_key_end = high 64 bits)
	p.s_key_begin = binary.LittleEndian.Uint64(key[16:])
	p.s_key_end = binary.LittleEndian.Uint64(key[24:])

	// Precomputation for code optimization
	p.s1_low = (p.r1 * (5 << 2)) & 0xffffffff
	p.s1_high = (p.r1 * (5 << 2)) >> 32

	p.s2_low = (p.r2 * (5 << 2)) & 0xffffffff
	p.s2_high = (p.r2 * (5 << 2)) >> 32

	return p, nil
}

func (this *Poly1305) ComputeHash(data []byte) (high_mac, low_mac uint64) {
	var r0, r1, r2, h0, h1, h2, c, c0, c1, c2 uint64
	var i, j, l uint
	var d, d0, d1, d2 [4]uint64
	var a0, a1, b0, b1, dst0, dst1, dst2, dst3 uint64

	l = uint(len(data))

	// Variables initialization: read 'r' and 's' as Little Endian unsigned int
	// r &= 0xffffffc0ffffffc0ffffffc0fffffff as required by the Poly1305 specifications
	//
	// NOTE: we need 'r', 'h' and 'c' to be uint130 because of the required modulus 2^130 - 5
	//       uint130(r) = 42 most significant bits(r2) + 44 middle bits(r1) + 44 less significant bits(r0)

	// r0 = LSB 44 bits of 'r' as uint130
	r0 = this.r0

	// r1 = middle 44 bits of 'r' as uint130
	r1 = this.r1

	// r2 = MSB 42 bits of 'r' as uint130
	r2 = this.r2

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

		// Calculate h = h * r

		// d0 = h0*r0 + h1*(r2*(5<<2)) + h2*(r1*(5<<2))
		//   step 1: d0 = h0*r0
		//   step 2: d  = h1*s2 (with s2 = r2*(5<<2))
		//   step 3: d0 += d
		//   step 4: d  = h2*s1 (with s1 = r1*(5<<2))
		//   step 5: d0 += d

		// step 1: d0 = h0*r0
		a0 = h0 & 0xffffffff
		a1 = h0 >> 32
		b0 = r0 & 0xffffffff
		b1 = r0 >> 32
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d0[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d0[1] = dst1 & 0xffffffff
		d0[2] = dst2 & 0xffffffff
		d0[3] = dst3 & 0xffffffff

		// step 2: d = h1*s2
		a0 = h1 & 0xffffffff
		a1 = h1 >> 32
		b0 = this.s2_low
		b1 = this.s2_high
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d[1] = dst1 & 0xffffffff
		d[2] = dst2 & 0xffffffff
		d[3] = dst3 & 0xffffffff

		// step 3: d0 += d
		dst0 = d0[0] + d[0]
		dst1 = d0[1] + d[1]
		dst2 = d0[2] + d[2]
		dst3 = d0[3] + d[3]
		dst1 += dst0 >> 32
		d0[0] = dst0 & 0xffffffff
		dst2 = dst2 + (dst1 >> 32)
		d0[1] = dst1 & 0xffffffff
		dst3 += (dst2 >> 32)
		d0[2] = dst2 & 0xffffffff
		d0[3] = dst3 & 0xffffffff

		// step 4: d = h2*s1
		a0 = h2 & 0xffffffff
		a1 = h2 >> 32
		b0 = this.s1_low
		b1 = this.s1_high
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d[1] = dst1 & 0xffffffff
		d[2] = dst2 & 0xffffffff
		d[3] = dst3 & 0xffffffff

		// step 5: d0 += d
		dst0 := d0[0] + d[0]
		dst1 := d0[1] + d[1]
		dst2 := d0[2] + d[2]
		dst3 := d0[3] + d[3]
		dst1 += dst0 >> 32
		d0[0] = dst0 & 0xffffffff
		dst2 = dst2 + (dst1 >> 32)
		d0[1] = dst1 & 0xffffffff
		dst3 += (dst2 >> 32)
		d0[2] = dst2 & 0xffffffff
		d0[3] = dst3 & 0xffffffff

		// d1 = h0*r1 + h1*r0 + h2*(r2*(5<<2))
		//   step 1: d1 = h0*r1
		//   step 2: d  = h1*r0
		//   step 3: d1 += d
		//   step 4: d  = h2*s2 (with s2 = r2*(5<<2))
		//   step 5: d1 += d

		// step 1: d1 = h0*r1
		a0 = h0 & 0xffffffff
		a1 = h0 >> 32
		b0 = r1 & 0xffffffff
		b1 = r1 >> 32
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d1[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d1[1] = dst1 & 0xffffffff
		d1[2] = dst2 & 0xffffffff
		d1[3] = dst3 & 0xffffffff

		// step 2: d = h1*r0
		a0 = h1 & 0xffffffff
		a1 = h1 >> 32
		b0 = r0 & 0xffffffff
		b1 = r0 >> 32
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d[1] = dst1 & 0xffffffff
		d[2] = dst2 & 0xffffffff
		d[3] = dst3 & 0xffffffff

		// step 3: d1 += d
		dst0 = d1[0] + d[0]
		dst1 = d1[1] + d[1]
		dst2 = d1[2] + d[2]
		dst3 = d1[3] + d[3]
		dst1 += dst0 >> 32
		d1[0] = dst0 & 0xffffffff
		dst2 = dst2 + (dst1 >> 32)
		d1[1] = dst1 & 0xffffffff
		dst3 += (dst2 >> 32)
		d1[2] = dst2 & 0xffffffff
		d1[3] = dst3 & 0xffffffff

		// step 4: d = h2*s2
		a0 = h2 & 0xffffffff
		a1 = h2 >> 32
		b0 = this.s2_low
		b1 = this.s2_high
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d[1] = dst1 & 0xffffffff
		d[2] = dst2 & 0xffffffff
		d[3] = dst3 & 0xffffffff

		// step 5: d1 += d
		dst0 = d1[0] + d[0]
		dst1 = d1[1] + d[1]
		dst2 = d1[2] + d[2]
		dst3 = d1[3] + d[3]
		dst1 += dst0 >> 32
		d1[0] = dst0 & 0xffffffff
		dst2 = dst2 + (dst1 >> 32)
		d1[1] = dst1 & 0xffffffff
		dst3 += (dst2 >> 32)
		d1[2] = dst2 & 0xffffffff
		d1[3] = dst3 & 0xffffffff

		// d2 = h0*r2 + h1*r1 + h2*r0
		//   step 1: d2 = h0*r2
		//   step 2: d  = h1*r1
		//   step 3: d2 += d
		//   step 4: d  = h2*r0
		//   step 5: d2 += d

		// step 1: d2 = h0*r2
		a0 = h0 & 0xffffffff
		a1 = h0 >> 32
		b0 = r2 & 0xffffffff
		b1 = r2 >> 32
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d2[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d2[1] = dst1 & 0xffffffff
		d2[2] = dst2 & 0xffffffff
		d2[3] = dst3 & 0xffffffff

		// step 2: d = h1*r1
		a0 = h1 & 0xffffffff
		a1 = h1 >> 32
		b0 = r1 & 0xffffffff
		b1 = r1 >> 32
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d[1] = dst1 & 0xffffffff
		d[2] = dst2 & 0xffffffff
		d[3] = dst3 & 0xffffffff

		// step 3: d2 += d
		dst0 = d2[0] + d[0]
		dst1 = d2[1] + d[1]
		dst2 = d2[2] + d[2]
		dst3 = d2[3] + d[3]
		dst1 += dst0 >> 32
		d2[0] = dst0 & 0xffffffff
		dst2 = dst2 + (dst1 >> 32)
		d2[1] = dst1 & 0xffffffff
		dst3 += (dst2 >> 32)
		d2[2] = dst2 & 0xffffffff
		d2[3] = dst3 & 0xffffffff

		// step 4: d = h2*r0
		a0 = h2 & 0xffffffff
		a1 = h2 >> 32
		b0 = r0 & 0xffffffff
		b1 = r0 >> 32
		dst0 = a0 * b0
		dst1 = dst0 >> 32
		d[0] = dst0 & 0xffffffff
		dst1 += a1 * b0
		dst2 = dst1 >> 32
		dst1 &= 0xffffffff
		dst1 += a0 * b1
		dst2 += dst1 >> 32
		dst3 = dst2 >> 32
		dst2 &= 0xffffffff
		dst2 += a1 * b1
		dst3 += dst2 >> 32
		d[1] = dst1 & 0xffffffff
		d[2] = dst2 & 0xffffffff
		d[3] = dst3 & 0xffffffff

		// step 5: d2 += d
		dst0 = d2[0] + d[0]
		dst1 = d2[1] + d[1]
		dst2 = d2[2] + d[2]
		dst3 = d2[3] + d[3]
		dst1 += dst0 >> 32
		d2[0] = dst0 & 0xffffffff
		dst2 = dst2 + (dst1 >> 32)
		d2[1] = dst1 & 0xffffffff
		dst3 += (dst2 >> 32)
		d2[2] = dst2 & 0xffffffff
		d2[3] = dst3 & 0xffffffff

		// partial h %= ((2^130)-5)
		// In fact we don't calculate the complete modulo value, but the lowest value that is < 2^130

		// Convert d (= uint128 simulated with 4 uint64 that contains 32+32+32+32 bits)
		// into h (= uint130 simulated with 3 uint64 that contains 42+44+44) and propagate the carry ( = c )

		// h0 = LSB 44 bits of d0
		c = (d0[1] >> 12) + (d0[2] << 20) + (d0[3] << 52)
		h0 = (d0[0] + (d0[1] << 32)) & 0xfffffffffff

		// h1 = LSB 44 bits of d1

		// addlo_reg(&d1, c)
		dst0 = d1[0] + (c & 0xffffffff)
		dst1 = d1[1] + (c >> 32)
		dst1 += dst0 >> 32
		d1[0] = dst0 & 0xffffffff
		dst2 = d1[2] + (dst1 >> 32)
		d1[1] = dst1 & 0xffffffff
		dst3 = d1[3] + (dst2 >> 32)
		d1[2] = dst2 & 0xffffffff
		d1[3] = dst3 & 0xffffffff

		c = (d1[1] >> 12) + (d1[2] << 20) + (d1[3] << 52)
		h1 = (d1[0] + (d1[1] << 32)) & 0xfffffffffff

		// h1 = LSB 42 bits of d2

		// addlo_reg(&d2, c)
		dst0 = d2[0] + (c & 0xffffffff)
		dst1 = d2[1] + (c >> 32)
		dst1 += dst0 >> 32
		d2[0] = dst0 & 0xffffffff
		dst2 = d2[2] + (dst1 >> 32)
		d2[1] = dst1 & 0xffffffff
		dst3 = d2[3] + (dst2 >> 32)
		d2[2] = dst2 & 0xffffffff
		d2[3] = dst3 & 0xffffffff

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
	c0 = this.s_key_begin
	c1 = this.s_key_end

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

	return h1, h0
}

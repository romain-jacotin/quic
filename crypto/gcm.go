package crypto

// computeGHash
func (this *AEAD_AES128GCM12) computeGHash(aad, ciphertext []byte) {

	// GHASH(H, A, C) = Xm+n+1 where the variables Xi for i = 0,...,m+n+1 are defined as:
	//
	// STEP 1:
	// X0 = 0
	//
	// STEP 2:
	// for i = 1,...,m−1
	//   Xi = (Xi-1 xor Ai) * H
	// end for
	//
	// STEP 3:
	// Xm = (Xm-1 xor (Am || 0^(128−v)) * H
	//
	// STEP 4:
	// for i = m+1,...,m+n−1
	//   Xi = (Xi−1 xor Ci−m) * H
	// end for
	//
	// STEP 5:
	// Xm+n = (Xm+n-1 xor (Cn||0^(128−u)) * H
	//
	// STEP 6:
	// Xm+n+1 = (Xm+n xor (len(A) || len(C))) * H

	var x0, x1, a0, a1, v0, v1, y0, y1 uint64
	var i, j, k, l uint32

	m := uint32(len(aad))
	modm := m & 0xf
	v := uint64(m) << 3
	m >>= 4

	n := uint32(len(ciphertext))
	modn := n & 0xf
	u := uint64(n) << 3
	n >>= 4

	// STEP 1: Compute X0 = 0
	// --> x0 = x1 = 0 (default uint64 value)

	// STEP 2: Compute X1 to Xm-1
	for i = 0; i < m; i++ {
		// Compute Ai (= little endian uint128 in two uint64)
		a0 = 0
		a1 = 0
		l = i << 4
		for j = 0; j < 8; j++ {
			a1 += uint64(aad[l]) << (56 - (j << 3))
			l++
		}
		for j = 8; j < 16; j++ {
			a0 += uint64(aad[l]) << (56 - ((j - 8) << 3))
			l++
		}
		// Compute Xi = (Xi−1 xor Ai) * H

		//x0, x1 = this.multH(x0^a0, x1^a1)
		v0 = x0 ^ a0
		v1 = x1 ^ a1
		x0 = 0
		x1 = 0
		y0 = this.h0
		y1 = this.h1
		for l = 0; l < 64; l++ {
			//   if Yi = 1 then Z = Z xor V
			if (y1 & (1 << (63 - l))) > 0 {
				x0 ^= v0
				x1 ^= v1
			}
			//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
			if (v0 & 1) == 0 {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
			} else {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
				v1 ^= 0xe100000000000000
				v0 ^= 0
			}
		}
		for l = 0; l < 64; l++ {
			//   if Yi = 1 then Z = Z xor V
			if (y0 & (1 << (63 - l))) > 0 {
				x0 ^= v0
				x1 ^= v1
			}
			//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
			if (v0 & 1) == 0 {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
			} else {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
				v1 ^= 0xe100000000000000
				v0 ^= 0
			}
		}
	}

	// STEP 3: Compute Xm = (Xm-1 xor (Am || 0^(128−v)) * H
	// Compute Am (= little endian uint128 in two uint64)
	if modm > 0 {
		a0 = 0
		a1 = 0
		if modm < 8 {
			k = modm
		} else {
			k = 8
		}
		l = m << 4
		for j = 0; j < k; j++ {
			a1 += uint64(aad[l]) << (56 - (j << 3))
			l++
		}
		if modm > 8 {
			k = modm
			for j = 8; j < k; j++ {
				a0 += uint64(aad[l]) << (56 - ((j - 8) << 3))
				l++
			}
		}
		// Compute Xm = (Xm-1 xor (Am || 0^(128−v)) * H

		// x0, x1 = this.multH(x0^a0, x1^a1)
		v0 = x0 ^ a0
		v1 = x1 ^ a1
		x0 = 0
		x1 = 0
		y0 = this.h0
		y1 = this.h1
		for l = 0; l < 64; l++ {
			//   if Yi = 1 then Z = Z xor V
			if (y1 & (1 << (63 - l))) > 0 {
				x0 ^= v0
				x1 ^= v1
			}
			//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
			if (v0 & 1) == 0 {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
			} else {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
				v1 ^= 0xe100000000000000
				v0 ^= 0
			}
		}
		for l = 0; l < 64; l++ {
			//   if Yi = 1 then Z = Z xor V
			if (y0 & (1 << (63 - l))) > 0 {
				x0 ^= v0
				x1 ^= v1
			}
			//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
			if (v0 & 1) == 0 {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
			} else {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
				v1 ^= 0xe100000000000000
				v0 ^= 0
			}
		}
	}

	// STEP 4: Compute Xm+1 to Xm+n-1
	for i = 0; i < n; i++ {
		// Compute Ci (= little endian uint128 in two uint64)
		a0 = 0
		a1 = 0
		l = i << 4
		for j = 0; j < 8; j++ {
			a1 += uint64(ciphertext[l]) << (56 - (j << 3))
			l++
		}
		for j = 8; j < 16; j++ {
			a0 += uint64(ciphertext[l]) << (56 - ((j - 8) << 3))
			l++
		}
		// Compute Xi = (Xi−1 xor Ci−m) * H

		// x0, x1 = this.multH(x0^a0, x1^a1)
		v0 = x0 ^ a0
		v1 = x1 ^ a1
		x0 = 0
		x1 = 0
		y0 = this.h0
		y1 = this.h1
		for l = 0; l < 64; l++ {
			//   if Yi = 1 then Z = Z xor V
			if (y1 & (1 << (63 - l))) > 0 {
				x0 ^= v0
				x1 ^= v1
			}
			//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
			if (v0 & 1) == 0 {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
			} else {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
				v1 ^= 0xe100000000000000
				v0 ^= 0
			}
		}
		for l = 0; l < 64; l++ {
			//   if Yi = 1 then Z = Z xor V
			if (y0 & (1 << (63 - l))) > 0 {
				x0 ^= v0
				x1 ^= v1
			}
			//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
			if (v0 & 1) == 0 {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
			} else {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
				v1 ^= 0xe100000000000000
				v0 ^= 0
			}
		}
	}

	// STEP 5: Compute Xm+n = (Xm+n-1 xor (Cn||0^(128−u)) * H
	if modn > 0 {
		a0 = 0
		a1 = 0
		// Compute Cn (= little endian uint128 in two uint64)
		if modn < 8 {
			k = modn
		} else {
			k = 8
		}
		l = n << 4
		for j = 0; j < k; j++ {
			a1 += uint64(ciphertext[l]) << (56 - (j << 3))
			l++
		}
		if modn > 8 {
			k = modn
			for j = 8; j < k; j++ {
				a0 += uint64(ciphertext[l]) << (56 - ((j - 8) << 3))
				l++
			}
		}
		// Compute Xm+n = (Xm+n-1 xor (Cn||0^(128−u)) * H

		// x0, x1 = this.multH(x0^a0, x1^a1)
		v0 = x0 ^ a0
		v1 = x1 ^ a1
		x0 = 0
		x1 = 0
		y0 = this.h0
		y1 = this.h1
		for l = 0; l < 64; l++ {
			//   if Yi = 1 then Z = Z xor V
			if (y1 & (1 << (63 - l))) > 0 {
				x0 ^= v0
				x1 ^= v1
			}
			//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
			if (v0 & 1) == 0 {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
			} else {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
				v1 ^= 0xe100000000000000
				v0 ^= 0
			}
		}
		for l = 0; l < 64; l++ {
			//   if Yi = 1 then Z = Z xor V
			if (y0 & (1 << (63 - l))) > 0 {
				x0 ^= v0
				x1 ^= v1
			}
			//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
			if (v0 & 1) == 0 {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
			} else {
				v0 >>= 1
				if (v1 & 1) == 1 {
					v0 |= 0x8000000000000000
				}
				v1 >>= 1
				v1 ^= 0xe100000000000000
				v0 ^= 0
			}
		}

	}

	// STEP 6: Xm+n+1 = (Xm+n xor (len(A) || len(C))) * H

	//x0, x1 = this.multH(x0^u, x1^v)
	v0 = x0 ^ u
	v1 = x1 ^ v
	x0 = 0
	x1 = 0
	y0 = this.h0
	y1 = this.h1
	for l = 0; l < 64; l++ {
		//   if Yi = 1 then Z = Z xor V
		if (y1 & (1 << (63 - l))) > 0 {
			x0 ^= v0
			x1 ^= v1
		}
		//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
		if (v0 & 1) == 0 {
			v0 >>= 1
			if (v1 & 1) == 1 {
				v0 |= 0x8000000000000000
			}
			v1 >>= 1
		} else {
			v0 >>= 1
			if (v1 & 1) == 1 {
				v0 |= 0x8000000000000000
			}
			v1 >>= 1
			v1 ^= 0xe100000000000000
			v0 ^= 0
		}
	}
	for l = 0; l < 64; l++ {
		//   if Yi = 1 then Z = Z xor V
		if (y0 & (1 << (63 - l))) > 0 {
			x0 ^= v0
			x1 ^= v1
		}
		//   if V127 = 0 then V = righshift( V ) else V = rightshift( V ) xor R
		if (v0 & 1) == 0 {
			v0 >>= 1
			if (v1 & 1) == 1 {
				v0 |= 0x8000000000000000
			}
			v1 >>= 1
		} else {
			v0 >>= 1
			if (v1 & 1) == 1 {
				v0 |= 0x8000000000000000
			}
			v1 >>= 1
			v1 ^= 0xe100000000000000
			v0 ^= 0
		}
	}

	// Write GHASH as Little Endian
	for i = 0; i < 8; i++ {
		this.ghash[i] = byte(x1 >> (56 - (i << 3)))
		this.ghash[i+8] = byte(x0 >> (56 - (i << 3)))
	}
}

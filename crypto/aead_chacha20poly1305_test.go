package crypto

import "testing"
import "bytes"

func Test_KeyGeneratorPoly1305(t *testing.T) {
	var buf [64]byte
	var cipher *ChaCha20Cipher
	var err error

	//  Poly1305 Key Generation Using ChaCha20 Test Vectors taken from RFC7539 : http://tools.ietf.org/html/rfc7539

	key := []byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f}
	noncePrefix := []byte{0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7}

	if cipher, err = NewChaCha20Cipher(key, noncePrefix, 0); err != nil {
		t.Error("Key Generator test for Poly1305 : error when calling NewChaCha20Cipher")
	}
	cipher.GetNextKeystream(&buf)
	if !bytes.Equal(buf[:32], []byte{
		0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
		0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46}) {
		t.Error("Key Generator test for Poly1305 : bad Poly1305 Key Generation test vector")
	}

	/*
	   Test Vector #1:
	   ==============

	   The key:
	   000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	   016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

	   The nonce:
	   000  00 00 00 00 00 00 00 00 00 00 00 00              ............

	   Poly1305 one-time key:
	   000  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28  v.....=.@]j.S..(
	   016  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7  .........6...w..
	*/
	key = make([]byte, 32)
	noncePrefix = make([]byte, 12)
	if cipher, err = NewChaCha20Cipher(key, noncePrefix, 0); err != nil {
		t.Error("Key Generator test for Poly1305 : error when calling NewChaCha20Cipher")
	}
	cipher.GetNextKeystream(&buf)
	if !bytes.Equal(buf[:32], []byte{
		0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
		0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7}) {
		t.Error("Key Generator test for Poly1305 : bad Poly1305 Key Generation test vector")
	}

	/*
	   Test Vector #2:
	   ==============

	   The key:
	   000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	   016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................

	   The nonce:
	   000  00 00 00 00 00 00 00 00 00 00 00 02              ............

	   Poly1305 one-time key:
	   000  ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76  ..%O._dts......v
	   016  06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39  ..3.lD{..&f....9
	*/
	key = []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	noncePrefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	if cipher, err = NewChaCha20Cipher(key, noncePrefix, 0); err != nil {
		t.Error("Key Generator test for Poly1305 : error when calling NewChaCha20Cipher")
	}
	cipher.GetNextKeystream(&buf)
	if !bytes.Equal(buf[:32], []byte{
		0xec, 0xfa, 0x25, 0x4f, 0x84, 0x5f, 0x64, 0x74, 0x73, 0xd3, 0xcb, 0x14, 0x0d, 0xa9, 0xe8, 0x76,
		0x06, 0xcb, 0x33, 0x06, 0x6c, 0x44, 0x7b, 0x87, 0xbc, 0x26, 0x66, 0xdd, 0xe3, 0xfb, 0xb7, 0x39}) {
		t.Error("Key Generator test for Poly1305 : bad Poly1305 Key Generation test vector")
	}

	/*
	   Test Vector #3:
	   ==============

	   The key:
	   000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
	   016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

	   The nonce:
	   000  00 00 00 00 00 00 00 00 00 00 00 02              ............

	   Poly1305 one-time key:
	   000  96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b  .^;...~.V....).K
	   016  13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae  ...u..?..Y...3..
	*/
	key = []byte{
		0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
		0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0}
	noncePrefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	if cipher, err = NewChaCha20Cipher(key, noncePrefix, 0); err != nil {
		t.Error("Key Generator test for Poly1305 : error when calling NewChaCha20Cipher")
	}
	cipher.GetNextKeystream(&buf)
	if !bytes.Equal(buf[:32], []byte{
		0x96, 0x5e, 0x3b, 0xc6, 0xf9, 0xec, 0x7e, 0xd9, 0x56, 0x08, 0x08, 0xf4, 0xd2, 0x29, 0xf9, 0x4b,
		0x13, 0x7f, 0xf2, 0x75, 0xca, 0x9b, 0x3f, 0xcb, 0xdd, 0x59, 0xde, 0xaa, 0xd2, 0x33, 0x10, 0xae}) {
		t.Error("Key Generator test for Poly1305 : bad Poly1305 Key Generation test vector")
	}

}

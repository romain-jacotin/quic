package crypto

import "testing"
import "encoding/binary"
import "bytes"

// Poly1305 Test Vectors taken from RFC7539 : http://tools.ietf.org/html/rfc7539

func Test_Poly1305(t *testing.T) {
	var mac_h, mac_l uint64
	var err error
	var p *Poly1305

	mac := make([]byte, 16)

	r_key := []byte{0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8}
	s_key := []byte{0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b}
	// Message = "Cryptographic Forum Research Group"
	m := []byte{0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f, 0x72,
		0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70}

	if p, err = NewPoly1305(append(r_key, s_key...)); err != nil {
		t.Error(err)
	}

	// MAC = a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9}) {
		t.Error("Poly1305 : invalid mac")
	}

	/*
	  Test Vector #1:
	  ==============

	  One-time Poly1305 Key:
	  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

	  Text to MAC:
	  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	  032  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	  048  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

	  Tag:
	  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	*/
	if p, err = NewPoly1305(make([]byte, 32)); err != nil {
		t.Error(err)
	}
	m = make([]byte, 64)
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Error("Poly1305 : invalid mac")
	}

	/*
	  Test Vector #2:
	  ==============

	  One-time Poly1305 Key:
	  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	  016  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>

	  Text to MAC:
	  000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
	  016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
	  032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
	  048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
	  064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
	  080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
	  096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
	  112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
	  128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
	  144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
	  160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
	  176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
	  192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an "IETF Cont
	  208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution". Such
	  224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
	  240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
	  256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
	  272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
	  288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
	  304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
	  320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
	  336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
	  352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
	  368  73 73 65 64 20 74 6f                             ssed to

	  Tag:
	  000  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>
	*/
	if p, err = NewPoly1305([]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e}); err != nil {
		t.Error(err)
	}
	m = []byte("Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to")
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e}) {
		t.Errorf("Poly1305 : invalid mac")
	}

	/*
	  Test Vector #3:
	  ==============

	  One-time Poly1305 Key:
	  000  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>
	  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

	  Text to MAC:
	  000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
	  016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
	  032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
	  048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
	  064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
	  080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
	  096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
	  112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
	  128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
	  144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
	  160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
	  176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
	  192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an "IETF Cont
	  208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution". Such
	  224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
	  240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
	  256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
	  272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
	  288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
	  304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
	  320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
	  336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
	  352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
	  368  73 73 65 64 20 74 6f                             ssed to

	  Tag:
	  000  f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0  .G~|.T.....yL1..
	*/
	if p, err = NewPoly1305([]byte{
		0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Error(err)
	}
	m = []byte("Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to")
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0xf3, 0x47, 0x7e, 0x7c, 0xd9, 0x54, 0x17, 0xaf, 0x89, 0xa6, 0xb8, 0x79, 0x4c, 0x31, 0x0c, 0xf0}) {
		t.Errorf("Poly1305 : invalid mac")
	}

	/*
	  Test Vector #4:
	  ==============

	  One-time Poly1305 Key:
	  000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
	  016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

	  Text to MAC:
	  000  27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61  'Twas brillig, a
	  016  6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f  nd the slithy to
	  032  76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64  ves.Did gyre and
	  048  20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77   gimble in the w
	  064  61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77  abe:.All mimsy w
	  080  65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65  ere the borogove
	  096  73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20  s,.And the mome
	  112  72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e     raths outgrabe.

	  Tag:
	  000  45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62  EAf.~..a...|...b
	*/
	if p, err = NewPoly1305([]byte{
		0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
		0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0}); err != nil {
		t.Error(err)
	}
	m = []byte("'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.")
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0x45, 0x41, 0x66, 0x9a, 0x7e, 0xaa, 0xee, 0x61, 0xe7, 0x08, 0xdc, 0x7c, 0xbc, 0xc5, 0xeb, 0x62}) {
		t.Errorf("Poly1305 : invalid mac")
	}

	/*
	   Test Vector #5: If one uses 130-bit partial reduction, does the code handle the case where partially reduced final result is not fully reduced?

	   R:
	   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   S:
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   data:
	   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	   tag:
	   03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	*/
	if p, err = NewPoly1305([]byte{
		2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Error(err)
	}
	m = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Poly1305 : invalid mac")
	}

	/*
	   Test Vector #6: What happens if addition of s overflows modulo 2^128?

	   R:
	   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   S:
	   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	   data:
	   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   tag:
	   03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	*/
	if p, err = NewPoly1305([]byte{
		2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); err != nil {
		t.Error(err)
	}
	m = []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Poly1305 : invalid mac")
	}

	/*
	   Test Vector #7: What happens if data limb is all ones and there is carry from lower limb?

	   R:
	   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   S:
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   data:
	   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	   F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	   11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   tag:
	   05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	*/
	if p, err = NewPoly1305([]byte{
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Error(err)
	}
	m = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Poly1305 : invalid mac")
	}

	/*
	   Test Vector #8: What happens if final result from polynomial part is exactly 2^130-5?

	   R:
	   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   S:
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   data:
	   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	   FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
	   01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
	   tag:
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	*/
	if p, err = NewPoly1305([]byte{
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Error(err)
	}
	m = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFB, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Poly1305 : invalid mac")
	}

	/*
	   Test Vector #9: What happens if final result from polynomial part is exactly 2^130-6?

	   R:
	   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   S:
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   data:
	   FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	   tag:
	   FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	*/
	if p, err = NewPoly1305([]byte{
		2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Error(err)
	}
	m = []byte{0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0xFA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Errorf("Poly1305 : invalid mac [%v]\n%x\n%x %x", len(m), m, mac, m[1])
	}

	/*
	   Test Vector #10: What happens if 5*H+L-type reduction produces 131-bit intermediate result?

	   R:
	   01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
	   S:
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   data:
	   E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
	   33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   tag:
	   14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00
	*/
	if p, err = NewPoly1305([]byte{
		1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Error(err)
	}
	m = []byte{
		0xE3, 0x35, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
		0x33, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0x79, 0xCD, 1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0x14, 0, 0, 0, 0, 0, 0, 0, 0x55, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Poly1305 : invalid mac")
	}

	/*
	   Test Vector #11: What happens if 5*H+L-type reduction produces 131-bit final result?

	   R:
	   01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
	   S:
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   data:
	   E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
	   33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
	   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	   tag:
	   13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	*/
	if p, err = NewPoly1305([]byte{
		1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Error(err)
	}
	m = []byte{
		0xE3, 0x35, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
		0x33, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0x79, 0xCD, 1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	mac_h, mac_l = p.ComputeMAC(m)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Poly1305 : invalid mac")
	}

}

func Test_ComputeAeadMAC(t *testing.T) {
	var mac_h, mac_l uint64
	var err error
	var p *Poly1305
	var cipher *ChaCha20Cipher
	var buf [64]byte

	// Test Vectors taken from RFC7539 Annexe 5 : http://tools.ietf.org/html/rfc7539

	/*
	   The key:
	   000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
	   016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

	   Ciphertext:
	   000  64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd  d...u...`.b...C.
	   016  5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2  ^.\.4\....g..l..
	   032  4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0  Ll..u]C....N8-&.
	   048  bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf  ...<2.....;.5X..
	   064  33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81  3/..q......J....
	   080  14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55  ...n..3.`....7.U
	   096  97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38  ...n...a..2N+5.8
	   112  36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4  6..{j|.....{S.g.
	   128  b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9  ..lv{.MF..R.....
	   144  90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e  .@...3"^.....lR>
	   160  af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a  .E4..?..[.Gq..Tj
	   176  0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a  ..+..VN..B"s.H'.
	   192  0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e  ..1`S.v..U..1YCN
	   208  ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10  ..NFm.Z.s.rv'.z.
	   224  49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30  I....6...h..w.q0
	   240  30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29  0[.......{qMlo,)
	   256  a6 ad 5c b4 02 2b 02 70 9b                       ..\..+.p.

	   The nonce:
	   000  00 00 00 00 01 02 03 04 05 06 07 08              ............

	   The AAD:
	   000  f3 33 88 86 00 00 00 00 00 00 4e 91              .3........N.

	   Received Tag:
	   000  ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38  ...g..."9#6....8
	*/
	key := []byte{
		0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
		0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0}
	aad := []byte{0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91}
	cipherText := []byte{
		0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
		0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
		0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
		0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
		0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
		0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
		0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61, 0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
		0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0, 0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
		0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
		0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
		0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
		0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea, 0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
		0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
		0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
		0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
		0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
		0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 0x9b}
	noncePrefix := []byte{0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	if cipher, err = NewChaCha20Cipher(key, noncePrefix, 0); err != nil {
		t.Error("Key Generator test for Poly1305 : error when calling NewChaCha20Cipher")
	}
	cipher.GetNextKeystream(&buf)
	if p, err = NewPoly1305(buf[:]); err != nil {
		t.Error(err)
	}
	mac_h, mac_l = p.ComputeAeadMAC(aad, cipherText)
	mac := make([]byte, 16)
	binary.LittleEndian.PutUint64(mac, mac_l)
	binary.LittleEndian.PutUint64(mac[8:], mac_h)
	if !bytes.Equal(mac, []byte{0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38}) {
		t.Error("ComputeAeadMAC : invalid MAC")
	}
}

package crypto

import "testing"
import "bytes"
import "strings"
import "encoding/binary"
import "github.com/romain-jacotin/quic/protocol"

type testVector struct {
	key        string
	nonce      string
	aad        string
	plaintext  string
	ciphertext string
	tag        string
}

var testsAES128GCM12 = []testVector{
	{
		// Test Case 1 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
		"00000000000000000000000000000000", // key
		"000000000000000000000000",         // nonce
		"", // aad
		"", // plain text
		"", // waiting cipher
		"58e2fccefa7e3061367f1d57a4e7455a"}, // waiting tag
	{
		// Test Case 2 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
		"00000000000000000000000000000000", // key
		"000000000000000000000000",         // nonce
		"", // aad
		"00000000000000000000000000000000",  // plain text
		"0388dace60b6a392f328c2b971b2fe78",  // waiting cipher
		"ab6e47d42cec13bdf53a67b21257bddf"}, // waiting tag
	{
		// Test Case 3 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
		"feffe9928665731c6d6a8f9467308308", // key
		"cafebabefacedbaddecaf888",         // nonce
		"", // aad
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", // plain text
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", // waiting cipher
		"4d5c2af327cd64a62cf35abd2ba6fab4"},                                                                                                // waiting tag
	{
		// Test Case 4 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
		"feffe9928665731c6d6a8f9467308308",                                                                                         // key
		"cafebabefacedbaddecaf888",                                                                                                 // nonce
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",                                                                                 // aad
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", // plain text
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", // waiting cipher
		"5bc94fbc3221a5db94fae95ae7121a47"},                                                                                        // waiting tag
}

func toByte(s string) []byte {
	bs := []byte(strings.ToLower(s))
	b := make([]byte, len(bs)/2)

	if len(bs) == 0 {
		return []byte{}
	}
	for i := 0; i < len(s)/2; i++ {
		switch bs[i*2] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			b[i] = (bs[i*2] - '0') << 4
		case 'a', 'b', 'c', 'd', 'e', 'f':
			b[i] = (bs[i*2] - 'a' + 10) << 4
		}
		switch bs[i*2+1] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			b[i] += (bs[i*2+1] - '0')
		case 'a', 'b', 'c', 'd', 'e', 'f':
			b[i] += (bs[i*2+1] - 'a' + 10)
		}
	}
	return b
}

func Test_AEAD_AES128GCM12_Open(t *testing.T) {
	var key, nonce, aad, plaintext, ciphertext, tag []byte

	for _, i := range testsAES128GCM12 {

		key = toByte(i.key)
		nonce = toByte(i.nonce)
		aad = toByte(i.aad)
		plaintext = toByte(i.plaintext)
		ciphertext = toByte(i.ciphertext)
		tag = toByte(i.tag)

		// fmt.Printf("\n~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\n\n")
		open(key, nonce, aad, plaintext, ciphertext, tag, t)
	}

}

func Test_AEAD_AES128GCM12_Seal(t *testing.T) {
	var key, nonce, aad, plaintext, ciphertext, tag []byte

	for _, i := range testsAES128GCM12 {

		key = toByte(i.key)
		nonce = toByte(i.nonce)
		aad = toByte(i.aad)
		plaintext = toByte(i.plaintext)
		ciphertext = toByte(i.ciphertext)
		tag = toByte(i.tag)

		//fmt.Printf("\n~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~\n\n")
		seal(key, nonce, aad, plaintext, ciphertext, tag, t)
	}

}

func seal(key, nonce, aad, plaintext, ciphertext, tag []byte, test *testing.T) {
	var bc int

	buffer := make([]byte, 1500)
	aead, err := NewAEAD_AES128GCM12(key, nonce)
	if bc, err = aead.Seal(protocol.QuicPacketSequenceNumber(binary.LittleEndian.Uint64(nonce[4:])), buffer, aad, plaintext); err != nil {
		test.Errorf("AEAD_AES128GCM12.Seal : Error return = %v", err)
	}
	if !bytes.Equal(ciphertext, buffer[:bc-12]) || !bytes.Equal(tag[:12], buffer[bc-12:bc]) {
		test.Errorf("----------------\nENCRYPTION TEST:\n----------------\nKey             : [%d] %x\nNonce           : [%d] %x\nAssociated data : [%d] %x\nPlain text      : [%d] %x\n\nCipher text     : [%d] %x\nTag             : [%d] %x\n\n    TEST STATUS = [ FAIL ]\n\n",
			len(key), key, len(nonce), nonce, len(aad), aad, len(plaintext), plaintext, bc-12, buffer[:bc-12], 12, buffer[bc-12:bc])
	}
}

func open(key, nonce, aad, plaintext, ciphertext, tag []byte, test *testing.T) {
	var bc int

	buffer := make([]byte, 1500)
	ct := append(ciphertext, tag[:12]...)
	aead, err := NewAEAD_AES128GCM12(key, nonce)
	if bc, err = aead.Open(protocol.QuicPacketSequenceNumber(binary.LittleEndian.Uint64(nonce[4:])), buffer, aad, ct); err != nil {
		test.Errorf("AEAD_AES128GCM12.Open : Error return = %v", err)
	}
	if !bytes.Equal(plaintext, buffer[:bc]) {
		test.Errorf("----------------\nDECRYPTION TEST:\n----------------\nKey             : [%d] %x\nNonce           : [%d] %x\nAssociated data : [%d] %x\nCipher text     : [%d] %x\nTag             : [%d] %x\n\nPlain text      : [%d] %x\n\n    TEST STATUS = [ FAIL ]\n\n",
			len(key), key, len(nonce), nonce, len(aad), aad, len(ciphertext), ciphertext, 12, buffer[bc-12:], bc, buffer[:bc-12])
	}
}

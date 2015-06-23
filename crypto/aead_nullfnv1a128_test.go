package crypto

import "testing"
import "bytes"

func Test_AEAD_NullFNV1A_128_Open(t *testing.T) {
	buffer := make([]byte, 1500)
	aad := []byte("All human beings are born free and equal in dignity and rights.")
	plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")
	hash := []byte{0x98, 0x9b, 0x33, 0x3f, 0xe8, 0xde, 0x32, 0x5c, 0xa6, 0x7f, 0x9c, 0xf7}
	cipherText := append(hash, plainText...)
	aead := NewAEAD_NullFNV1A128()
	c, err := aead.Open(42, buffer, aad, cipherText)
	if err != nil {
		t.Error(err)
	}
	if c != len(plainText) {
		t.Error("AEAD_NullFNV1A_128.Open: bad decrypted length")
	}
	if !bytes.Equal(plainText, buffer[:c]) {
		t.Error("AEAD_NullFNV1A_128.Open: invalid decrypted plaintext")
	}
}

func Test_AEAD_NullFNV1A_128_Seal(t *testing.T) {
	buffer := make([]byte, 1500)
	aad := []byte("All human beings are born free and equal in dignity and rights.")
	plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")
	hash := []byte{0x98, 0x9b, 0x33, 0x3f, 0xe8, 0xde, 0x32, 0x5c, 0xa6, 0x7f, 0x9c, 0xf7}
	aead := NewAEAD_NullFNV1A128()
	c, err := aead.Seal(42, buffer, aad, plainText)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(hash, buffer[:12]) {
		t.Errorf("AEAD_NullFNV1A_128.Seal: invalid AEAD Hash")
	}
	if !bytes.Equal(plainText, buffer[12:c]) {
		t.Error("AEAD_NullFNV1A_128.Seal: invalid encrypted plaintext")
	}
}

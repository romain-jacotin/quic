package crypto

import "github.com/romain-jacotin/quic/protocol"
import "errors"
import "encoding/binary"
import "fmt"

type AEAD_NullFNV1A128 struct {
}

// NewAEAD_NullFNV1A128 returns a *AEAD_NullFNV1A128 that implements an AEAD interface with null encryption and FNV1A-128 hash truncated to 96-bit
func NewAEAD_NullFNV1A128() AEAD {
	return new(AEAD_NullFNV1A128)
}

// Open
func (this *AEAD_NullFNV1A128) Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, aad, ciphertext []byte) (bytescount int, err error) {
	// Check the Hash
	l := len(ciphertext) - 12
	if l < 0 {
		err = errors.New("AEAD_NullFNV1A128.Open : Hash can't be less than 12 bytes")
		return
	}
	low := binary.LittleEndian.Uint64(ciphertext)
	high := binary.LittleEndian.Uint32(ciphertext[8:])
	testhigh, testlow := ComputeAeadHashFNV1A_128(aad, ciphertext[12:])
	if (low != testlow) || (high != uint32(testhigh&0xffffffff)) {
		err = fmt.Errorf("AEAD_NullFNV1A128.Open : invalid Hash verification %x:%x versus %x:%x", low, high, testlow, testhigh)
		return
	}
	// Then Copy (without decryption)
	copy(plaintext[:l], ciphertext[12:])
	bytescount = l
	return
}

// Seal
func (this *AEAD_NullFNV1A128) Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, aad, plaintext []byte) (bytescount int, err error) {
	l := len(plaintext)
	if len(ciphertext) < (l + 12) {
		err = errors.New("AEAD_NullFNV1A128.Seal : ciphertext can't be less than plaintext + 12 bytes")
		return
	}
	// Hash
	high, low := ComputeAeadHashFNV1A_128(aad, plaintext)
	binary.LittleEndian.PutUint64(ciphertext, low)
	binary.LittleEndian.PutUint32(ciphertext[8:], uint32(high))
	// Then Copy (without encryption)
	copy(ciphertext[12:], plaintext)
	bytescount = l + 12
	return
}

// GetMacSize
func (this *AEAD_NullFNV1A128) GetMacSize() int {
	return 12
}

package crypto

import "github.com/romain-jacotin/quic/protocol"
import "encoding/binary"
import "errors"
import "fmt"

type AEAD_ChaCha20Poly1305 struct {
	cipher *ChaCha20Cipher
	hasher *Poly1305
}

// NewAEAD_ChaCha20Poly1305 returns a *AEAD_ChaCha20Poly1305 that implements AEAD interface
func NewAEAD_ChaCha20Poly1305(key, nonceprefix []byte) (AEAD, error) {
	var buf [64]byte
	var err error

	if len(key) < 32 {
		return nil, errors.New("AEAD_ChaCha20Poly1305 : AEAD_CHACHA20_POLY1305_12 requires 256-bit key")
	}
	if len(nonceprefix) < 4 {
		return nil, errors.New("AEAD_ChaCha20Poly1305 : QUIC requires 32-bit nonce prefix")
	}

	aead := new(AEAD_ChaCha20Poly1305)
	if aead.cipher, err = NewChaCha20Cipher(key, nonceprefix, 0); err != nil {
		return nil, errors.New("AEAD_ChaCha20Poly1305 : error when calling NewChaCha20Cipher")
	}
	aead.cipher.GetNextKeystream(&buf)
	if aead.hasher, err = NewPoly1305(buf[0:32]); err != nil {
		return nil, errors.New("AEAD_ChaCha20Poly1305 : error when calling NewPoly1305")
	}
	return aead, nil
}

// Open
func (this *AEAD_ChaCha20Poly1305) Open(sequencenumber protocol.QuicPacketSequenceNumber, cleartext, aad, ciphertext []byte) error {
	// Check the MAC
	l := len(ciphertext)
	if l < 12 {
		return errors.New("AEAD_ChaCha20Poly1305 : Message Authentication Code can't be less than 12 bytes")
	}
	low := binary.LittleEndian.Uint64(ciphertext[l-12:])
	high := binary.LittleEndian.Uint32(ciphertext[l-4:])
	testhigh, testlow := this.hasher.ComputeAeadMAC(aad, ciphertext[:l-12])
	if (low != testlow) || (high != uint32(testhigh&0xffffffff)) {
		return fmt.Errorf("AEAD_ChaCha20Poly1305 : invalid Message Authentication Code %x:%x versus %x:%x", low, high, testlow, testhigh)
	}
	// Then decrypt
	this.cipher.SetPacketSequenceNumber(sequencenumber)

	return nil
}

// Seal
func (this *AEAD_ChaCha20Poly1305) Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, aad, plaintext []byte) error {
	return nil
}
